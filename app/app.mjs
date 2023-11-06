import jwt from "./jwt.js";
import secretsManager from "./secrets-manager.mjs";

const generatePolicy = function(principalId, effect, resource) {
    return {
        "principalId": principalId,
        "policyDocument": {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Action": "execute-api:Invoke",
                    "Effect": effect,
                    "Resource": resource
                }
            ]
        }
    };
};

export const handler = async (event) => {
    try {
        console.log(`Event: ${JSON.stringify(event)}`);

        const authorization = event.authorizationToken;
        const verifierParams = await secretsManager.retrieve(process.env.VERIFIER_SECRET_ID);
        const token = await jwt.verify(authorization, verifierParams);

        return generatePolicy(token.uuid, 'Allow', event.methodArn);
    } catch (error) {
        console.error(error);
        return generatePolicy('undefined', 'Unauthorized', event.methodArn);
    }
};