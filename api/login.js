import { IDENTITY_SERVER_URL } from "../config/constants";

export const login = async ({
    passPhrase
}) => {
    try {
        const res = await fetch(`${IDENTITY_SERVER_URL}/auth/login/`, {
            method: "POST",
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify({ pass_phrase: passPhrase })
        });

        if (!res.ok) {
            throw new Error(`HTTP error! status: ${res.status}`);
        }

        return await res.json();
    } catch (err) {
        console.error("Error during login:", err);
        throw err;
    }
};