import fb, { ServiceAccount } from "firebase-admin";  
import { getAuth } from "firebase-admin/auth";
import { getFirestore } from "firebase-admin/firestore";
import serviceAccount from "../portfolioproject-57fd8-firebase-adminsdk-3a4wf-9aba14a196.json" with { type: "json" };

export const firebaseApp = fb.initializeApp({
    credential: fb.credential.cert(serviceAccount as ServiceAccount)
}); 
export const auth = getAuth(firebaseApp);
export const db = getFirestore(firebaseApp);