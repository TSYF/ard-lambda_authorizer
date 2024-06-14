export interface Statement {
    Action: string;
    Effect: string;
    Resource: string[];
    Condition?: Record<string, any>;
}