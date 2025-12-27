import { db } from "@/db/db";
import { Request, Response } from "express";

/* Helper to serialize BigInt for JSON */
function serializeBigInt(obj: any): any {
  return JSON.parse(
    JSON.stringify(obj, (key, value) =>
      typeof value === "bigint" ? value.toString() : value
    )
  );
}

/* UPDATE WATCH PROGRESS */
export async function updateWatchProgress(req: Request, res: Response) {
  const { userId, movieId, seriesId, episodeId, currentTime, duration } = req.body;

  try {
    // Validation
    if (!userId) {
      return res.status(400).json({ data: null, error: "User ID is required" });
    }

    if (!movieId && !episodeId) {
      return res.status(400).json({
        data: null,
        error: "Either movieId or episodeId is required",
      });
    }

    if (currentTime === undefined || duration === undefined) {
      return res.status(400).json({
        data: null,
        error: "currentTime and duration are required",
      });
    }

    // Calculate progress percentage
    const progressPercent = (currentTime / duration) * 100;
    const completed = progressPercent >= 90; // Consider 90% as completed

    if (movieId) {
      // Update or create movie watch history
      const watchHistory = await db.watchHistory.upsert({
        where: {
          userId_movieId: {
            userId,
            movieId,
          },
        },
        update: {
          currentTime,
          duration,
          progressPercent,
          completed,
          lastWatchedAt: new Date(),
        },
        create: {
          userId,
          movieId,
          currentTime,
          duration,
          progressPercent,
          completed,
        },
        include: {
          movie: {
            include: {
              vj: true,
              genre: true,
              year: true,
            },
          },
        },
      });

      return res.status(200).json({
        data: serializeBigInt(watchHistory),
        error: null,
      });
    }

    if (episodeId) {
      // Update or create episode watch history
      const watchHistory = await db.watchHistory.upsert({
        where: {
          userId_episodeId: {
            userId,
            episodeId,
          },
        },
        update: {
          currentTime,
          duration,
          progressPercent,
          completed,
          seriesId: seriesId || undefined,
          lastWatchedAt: new Date(),
        },
        create: {
          userId,
          episodeId,
          seriesId: seriesId || undefined,
          currentTime,
          duration,
          progressPercent,
          completed,
        },
        include: {
          episode: {
            include: {
              season: {
                include: {
                  series: {
                    include: {
                      vj: true,
                      genre: true,
                      year: true,
                    },
                  },
                },
              },
            },
          },
        },
      });

      return res.status(200).json({
        data: serializeBigInt(watchHistory),
        error: null,
      });
    }
  } catch (error) {
    console.error("Error updating watch progress:", error);
    return res.status(500).json({
      data: null,
      error: "Failed to update watch progress",
    });
  }
}

/* GET USER'S WATCH HISTORY */
export async function getWatchHistory(req: Request, res: Response) {
  const { userId } = req.params;
  const { type, limit = 20 } = req.query;

  try {
    if (!userId) {
      return res.status(400).json({ data: null, error: "User ID is required" });
    }

    const where: any = { userId };

    if (type === "movies") {
      where.movieId = { not: null };
    } else if (type === "series") {
      where.episodeId = { not: null };
    }

    const watchHistory = await db.watchHistory.findMany({
      where,
      orderBy: { lastWatchedAt: "desc" },
      take: Number(limit),
      include: {
        movie: {
          include: {
            vj: true,
            genre: true,
            year: true,
          },
        },
        episode: {
          include: {
            season: {
              include: {
                series: {
                  include: {
                    vj: true,
                    genre: true,
                    year: true,
                  },
                },
              },
            },
          },
        },
        series: {
          include: {
            vj: true,
            genre: true,
            year: true,
          },
        },
      },
    });

    return res.status(200).json({
      data: serializeBigInt(watchHistory),
      error: null,
    });
  } catch (error) {
    console.error("Error fetching watch history:", error);
    return res.status(500).json({
      data: null,
      error: "Failed to fetch watch history",
    });
  }
}

/* GET CONTINUE WATCHING */
export async function getContinueWatching(req: Request, res: Response) {
  const { userId } = req.params;
  const { limit = 10 } = req.query;

  try {
    if (!userId) {
      return res.status(400).json({ data: null, error: "User ID is required" });
    }

    // Get items that are not completed (less than 90% watched)
    const continueWatching = await db.watchHistory.findMany({
      where: {
        userId,
        completed: false,
        progressPercent: {
          gte: 5, // At least 5% watched (to exclude accidental clicks)
        },
      },
      orderBy: { lastWatchedAt: "desc" },
      take: Number(limit),
      include: {
        movie: {
          include: {
            vj: true,
            genre: true,
            year: true,
          },
        },
        episode: {
          include: {
            season: {
              include: {
                series: {
                  include: {
                    vj: true,
                    genre: true,
                    year: true,
                  },
                },
              },
            },
          },
        },
        series: {
          include: {
            vj: true,
            genre: true,
            year: true,
          },
        },
      },
    });

    return res.status(200).json({
      data: serializeBigInt(continueWatching),
      error: null,
    });
  } catch (error) {
    console.error("Error fetching continue watching:", error);
    return res.status(500).json({
      data: null,
      error: "Failed to fetch continue watching",
    });
  }
}

/* GET WATCH PROGRESS FOR SPECIFIC ITEM */
export async function getWatchProgress(req: Request, res: Response) {
  const { userId, movieId, episodeId } = req.query;

  try {
    if (!userId) {
      return res.status(400).json({ data: null, error: "User ID is required" });
    }

    if (!movieId && !episodeId) {
      return res.status(400).json({
        data: null,
        error: "Either movieId or episodeId is required",
      });
    }

    let watchHistory = null;

    if (movieId) {
      watchHistory = await db.watchHistory.findUnique({
        where: {
          userId_movieId: {
            userId: userId as string,
            movieId: movieId as string,
          },
        },
      });
    }

    if (episodeId) {
      watchHistory = await db.watchHistory.findUnique({
        where: {
          userId_episodeId: {
            userId: userId as string,
            episodeId: episodeId as string,
          },
        },
      });
    }

    return res.status(200).json({
      data: watchHistory ? serializeBigInt(watchHistory) : null,
      error: null,
    });
  } catch (error) {
    console.error("Error fetching watch progress:", error);
    return res.status(500).json({
      data: null,
      error: "Failed to fetch watch progress",
    });
  }
}

/* DELETE WATCH HISTORY ITEM */
export async function deleteWatchHistoryItem(req: Request, res: Response) {
  const { id } = req.params;

  try {
    await db.watchHistory.delete({
      where: { id },
    });

    return res.status(200).json({
      data: null,
      message: "Watch history item deleted",
    });
  } catch (error) {
    console.error("Error deleting watch history:", error);
    return res.status(500).json({
      data: null,
      error: "Failed to delete watch history",
    });
  }
}

/* CLEAR ALL WATCH HISTORY */
export async function clearWatchHistory(req: Request, res: Response) {
  const { userId } = req.params;

  try {
    await db.watchHistory.deleteMany({
      where: { userId },
    });

    return res.status(200).json({
      data: null,
      message: "Watch history cleared",
    });
  } catch (error) {
    console.error("Error clearing watch history:", error);
    return res.status(500).json({
      data: null,
      error: "Failed to clear watch history",
    });
  }
}