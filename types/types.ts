export type UserRole = "ADMIN" | "STAFF" | "STUDENT" | "PARENT" | "SUPER_ADMIN";


export interface UserCreateProps {
    email: string;
    username: string;
    password: string;
    firstName: string;
    lastName: string;
    role:       UserRole;
    phone?:     string
    image:      string 
  }