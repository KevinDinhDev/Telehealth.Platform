// Function to dynamically update the navigation bar based on user authentication status
async function updateNavbar() {
    try {
        // Make a GET request to check the user's authentication status
        const response = await fetch('/user', {
            method: 'GET',
            headers: {
                'Content-Type': 'application/json',
            },
        });

        if (response.ok) {
            // User is authenticated
            const user = await response.json();
            const userFirstName = 'test';

            // Update the navigation bar
            const nav = document.querySelector('nav');
            nav.innerHTML = `
                <div class="container">
                    <h1><a href="index.html"><img src="logo.JPG" alt="Telehealth Platform Logo"></a></h1>
                    <ul>
                        <li><a href="#about">About</a></li>
                        <li><a href="#features">Features</a></li>
                        <li><a href="#contact">Contact</a></li>
                        <li class="auth-link"><a href="#" onclick="signOut()">Sign Out</a></li>
                        <li class="user-welcome">Welcome, ${userFirstName}</li>
                    </ul>
                </div>
            `;
        } else {
            // User is not authenticated, show the default navigation bar
            const nav = document.querySelector('nav');
            nav.innerHTML = `
                <div class="container">
                    <h1><a href="index.html"><img src="logo.JPG" alt="Telehealth Platform Logo"></a></h1>
                    <ul>
                        <li><a href="#about">About</a></li>
                        <li><a href="#features">Features</a></li>
                        <li><a href="#contact">Contact</a></li>
                        <li class="auth-link"><a href="sign_in.html">Sign In</a></li>
                        <li class="auth-link register">
                            <a href="register_provider.html" onclick="window.location.href='register_provider.html'; return false;">Register as Provider</a>
                        </li>
                        <li class="auth-link register">
                            <a href="register_patient.html" onclick="window.location.href='register_patient.html'; return false;">Register as Patient</a>
                        </li>
                    </ul>
                </div>
            `;
        }
    } catch (error) {
        console.error('Error checking authentication status:', error);
    }
}
