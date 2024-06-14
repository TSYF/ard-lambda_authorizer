import { DocumentData, Firestore } from "firebase-admin/firestore";

export function getFirestoreUser(db: Firestore, uid: string): Promise<DocumentData> { 
    return new Promise((resolve, reject) => {
        db.collection("users")
            .doc(uid)
            .onSnapshot((doc) => {
                if (doc.exists) {
                    const data = doc.data()
                    if (data) {
                        return resolve(data);
                    }
                }
                reject("User not found in Firestore");
            }, (error) => {
                reject(error);
            });
    });
}
