import { AuthResponse } from './AuthResponse.mjs';
import { HttpVerb } from './HttpVerb.mjs';
import { Statement } from './Statement.mjs';

export class AuthPolicy {
  // The AWS account id the policy will be generated for. This is used to create the method ARNs.
  awsAccountId = '';
  // The principal used for the policy, this should be a unique identifier for the end user.
  principalId = '';
  // The policy version used for the evaluation. This should always be '2012-10-17'
  version = '2012-10-17';
  // The regular expression used to validate resource paths for the policy
  pathRegex = '^[/.a-zA-Z0-9-\*]+$';

  /**
   * Internal lists of allowed and denied methods.
   *
   * These are lists of objects and each object has 2 properties: A resource
   * ARN and a nullable conditions statement. The build method processes these
   * lists and generates the appropriate statements for the final policy.
   */
  allowMethods: { resourceArn: string; conditions: Record<string, any> | null }[] = [];
  denyMethods: { resourceArn: string; conditions: Record<string, any> | null }[] = [];

  /**
   * Replace the placeholder value with a default API Gateway API id to be used in the policy.
   * Beware of using '*' since it will not simply mean any API Gateway API id, because stars will greedily expand over '/' or other separators.
   * See https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_resource.html for more details.
   */
  restApiId = '<<restApiId>>';

  /**
   * Replace the placeholder value with a default region to be used in the policy.
   * Beware of using '*' since it will not simply mean any region, because stars will greedily expand over '/' or other separators.
   * See https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_resource.html for more details.
   */
  region = 'us-east-1';

  /**
   * Replace the placeholder value with a default stage to be used in the policy.
   * Beware of using '*' since it will not simply mean any stage, because stars will greedily expand over '/' or other separators.
   * See https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_resource.html for more details.
   */
  stage = '<<stage>>';

  constructor(principal: string, awsAccountId: string) {
    this.awsAccountId = awsAccountId;
    this.principalId = principal;
  }

  private _addMethod(
    effect: 'Allow' | 'Deny',
    verb: HttpVerb,
    resource: string,
    conditions: Record<string, any> | null
  ): void {
    /**
     * Adds a method to the internal lists of allowed or denied methods. Each object in
     * the internal list contains a resource ARN and a condition statement. The condition
     * statement can be null.
     */
    if (verb !== HttpVerb.ALL && !Object.values(HttpVerb).includes(verb)) {
      throw new Error(`Invalid HTTP verb ${verb}. Allowed verbs in HttpVerb class`);
    }

    const resourcePattern = new RegExp(this.pathRegex);
    if (!resourcePattern.test(resource)) {
      throw new Error(`Invalid resource path: ${resource}. Path should match ${this.pathRegex}`);
    }

    const resourcePath = resource.startsWith('/') ? resource.slice(1) : resource;

    const resourceArn = `arn:aws:execute-api:${this.region}:${this.awsAccountId}:${this.restApiId}/${this.stage}/${verb}/${resourcePath}`;

    if (effect === 'Allow') {
      this.allowMethods.push({
        resourceArn,
        conditions,
      });
    } else {
      this.denyMethods.push({
        resourceArn,
        conditions,
      });
    }
  }

  private _getEmptyStatement(effect: 'Allow' | 'Deny'): Statement {
    /**
     * Returns an empty statement object prepopulated with the correct action and the
     * desired effect.
     */
    return {
      Action: 'execute-api:Invoke',
      Effect: effect.charAt(0).toUpperCase() + effect.slice(1).toLowerCase(),
      Resource: [],
    };
  }

  private _getStatementForEffect(
    effect: 'Allow' | 'Deny',
    methods: { resourceArn: string; conditions: Record<string, any> | null }[]
  ): {
    Action: string;
    Effect: string;
    Resource: string[];
    Condition?: Record<string, any>;
  }[] {
    /**
     * This function loops over an array of objects containing a resourceArn and
     * conditions statement and generates the array of statements for the policy.
     */
    const statements: {
      Action: string;
      Effect: string;
      Resource: string[];
      Condition?: Record<string, any>;
    }[] = [];

    if (methods.length > 0) {
      const statement = this._getEmptyStatement(effect);

      for (const curMethod of methods) {
        if (curMethod.conditions === null || Object.keys(curMethod.conditions).length === 0) {
          statement.Resource.push(curMethod.resourceArn);
        } else {
          const conditionalStatement = this._getEmptyStatement(effect);
          conditionalStatement.Resource.push(curMethod.resourceArn);
          conditionalStatement.Condition = curMethod.conditions;
          statements.push(conditionalStatement);
        }
      }

      if (statement.Resource.length > 0) {
        statements.push(statement);
      }
    }

    return statements;
  }

  allowAllMethods(): void {
    /**
     * Adds a '*' allow to the policy to authorize access to all methods of an API
     */
    this._addMethod('Allow', HttpVerb.ALL, '*', null);
  }

  denyAllMethods(): void {
    /**
     * Adds a '*' allow to the policy to deny access to all methods of an API
     */
    this._addMethod('Deny', HttpVerb.ALL, '*', null);
  }

  allowMethod(verb: HttpVerb, resource: string): void {
    /**
     * Adds an API Gateway method (Http verb + Resource path) to the list of allowed
     * methods for the policy
     */
    this._addMethod('Allow', verb, resource, null);
  }

  denyMethod(verb: HttpVerb, resource: string): void {
    /**
     * Adds an API Gateway method (Http verb + Resource path) to the list of denied
     * methods for the policy
     */
    this._addMethod('Deny', verb, resource, null);
  }

  allowMethodWithConditions(
    verb: HttpVerb,
    resource: string,
    conditions: Record<string, any>
  ): void {
    /**
     * Adds an API Gateway method (Http verb + Resource path) to the list of allowed
     * methods and includes a condition for the policy statement. More on AWS policy
     * conditions here: http://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements.html#Condition
     */
    this._addMethod('Allow', verb, resource, conditions);
  }

  denyMethodWithConditions(
    verb: HttpVerb,
    resource: string,
    conditions: Record<string, any>
  ): void {
    /**
     * Adds an API Gateway method (Http verb + Resource path) to the list of denied
     * methods and includes a condition for the policy statement. More on AWS policy
     * conditions here: http://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements.html#Condition
     */
    this._addMethod('Deny', verb, resource, conditions);
  }

  build(): AuthResponse {
    /**
     * Generates the policy document based on the internal lists of allowed and denied
     * conditions. This will generate a policy with two main statements for the effect:
     * one statement for Allow and one statement for Deny.
     * Methods that include conditions will have their own statement in the policy.
     */
    if (
      (this.allowMethods === null || this.allowMethods.length === 0) &&
      (this.denyMethods === null || this.denyMethods.length === 0)
    ) {
      throw new Error('No statements defined for the policy');
    }
  
    const policy = {
      principalId: this.principalId,
      policyDocument: {
        Version: this.version,
        Statement: [] as Statement[],
      },
    };
  
    policy.policyDocument.Statement.push(...this._getStatementForEffect('Allow', this.allowMethods));
    policy.policyDocument.Statement.push(...this._getStatementForEffect('Deny', this.denyMethods));
  
    return policy;
  }
}