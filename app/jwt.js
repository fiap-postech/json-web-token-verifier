import jsonwebtoken from "jsonwebtoken";

export default {

    verify: (authorization, verifierParams) => new Promise(async (resolve, reject) => {
        const token = authorization ? authorization.substring(7) : null;
        if (!token) {
            reject({
                message: "Missing authentication token"
            });
        }

        jsonwebtoken.verify(token, verifierParams.publicKey, { algorithms: verifierParams.algorithm }, (error, decoded) => {
            if (error) {
                console.error(`Error: ${error}`);
                reject(error);
            } else {
                resolve({
                    uuid: decoded.uuid
                });
            }
        });
    })

}