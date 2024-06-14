export interface AuthResponse {
    principalId: string;
    policyDocument: {
      Version: string;
      Statement: {
        Action: string;
        Effect: string;
        Resource: string[];
        Condition?: Record<string, any>;
      }[];
    };
    context?: Record<string, any>;
}