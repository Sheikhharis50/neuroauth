export const login = async (pass_phrase) => {
    try {
        const res = await fetch("https://api.prod.auth.neuronus.net/api/auth/login/", {
            method: "POST",
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify({ pass_phrase: pass_phrase })
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