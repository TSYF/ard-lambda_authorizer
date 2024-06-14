import { AuthPolicy } from './tools/AuthPolicy.mjs';
import { HttpVerb } from './tools/HttpVerb.mjs';
import { auth, db } from './tools/firebaseConfig.mjs';
import { getFirestoreUser } from './tools/utils.mjs';

export const handler = async (event: any, context: any): Promise<any> => {
   
    const prefix = "Bearer ";
    const header: string = event.authorizationToken;
    const token = header.substring(prefix.length);

    let user;
    let principalId = 'ar_detailing|guest';

    const policy = new AuthPolicy(principalId, '067520872288');
    policy.restApiId = '029t1z0lil';
    policy.region = 'us-east-2';
    policy.stage = 'ar_detailing';
    // policy.denyAllMethods();
        
    policy.allowMethod(HttpVerb.GET, '/api/service');
    policy.allowMethod(HttpVerb.GET, '/api/service/*');
    
    policy.allowMethod(HttpVerb.GET, '/api/example');
    policy.allowMethod(HttpVerb.GET, '/api/example/*');

    policy.allowMethod(HttpVerb.POST, '/api/message');
    policy.allowMethod(HttpVerb.POST, '/api/reservation');

    try {
        user = await auth.verifyIdToken(token)
        principalId = user.uid;

        const firestoreUser = await getFirestoreUser(db, user.uid);
        if (firestoreUser.isAdmin) {
            policy.allowAllMethods();
        }
        
    } catch (error) {
        console.log(error);
    }

    // Finally, build the policy :D
    return policy.build();
};