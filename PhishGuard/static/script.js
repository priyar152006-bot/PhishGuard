// =====================================
// LOADER
// =====================================

window.addEventListener("load", function () {

    const loader = document.getElementById("loader");

    if (loader) {

        setTimeout(() => {

            loader.style.opacity = "0";

            setTimeout(() => {

                loader.style.display = "none";

            }, 500);

        }, 1200);

    }

});

// =====================================
// FAQ ACCORDION
// =====================================

const faqItems = document.querySelectorAll(".faq-item");

faqItems.forEach(item => {

    const button = item.querySelector(".faq-question");

    if (button) {

        button.addEventListener("click", () => {

            faqItems.forEach(other => {

                if (other !== item) {

                    other.classList.remove("active");

                }

            });

            item.classList.toggle("active");

        });

    }

});

// =====================================
// COPY URL
// =====================================

function copyURL() {

    const url = document.querySelector(".url-box");

    if (url) {

        navigator.clipboard.writeText(url.innerText);

        showToast("✅ URL Copied Successfully");

    }

}

// =====================================
// TOAST MESSAGE
// =====================================

function showToast(message) {

    const toast = document.createElement("div");

    toast.className = "toast";

    toast.innerHTML = message;

    document.body.appendChild(toast);

    setTimeout(() => {

        toast.classList.add("show");

    }, 100);

    setTimeout(() => {

        toast.remove();

    }, 3000);

}

// =====================================
// SCROLL TO TOP
// =====================================

const scrollBtn = document.getElementById("scrollTop");

if (scrollBtn) {

    window.addEventListener("scroll", () => {

        if (window.scrollY > 300) {

            scrollBtn.style.display = "block";

        }

        else {

            scrollBtn.style.display = "none";

        }

    });

    scrollBtn.onclick = function () {

        window.scrollTo({

            top: 0,

            behavior: "smooth"

        });

    };

}

// =====================================
// COUNTER ANIMATION
// =====================================

const counters = document.querySelectorAll(".counter");

counters.forEach(counter => {

    const update = () => {

        const target = +counter.getAttribute("data-target");

        const count = +counter.innerText;

        const speed = 60;

        const inc = target / speed;

        if (count < target) {

            counter.innerText = Math.ceil(count + inc);

            setTimeout(update, 30);

        }

        else {

            counter.innerText = target;

        }

    };

    update();

});

// =====================================
// NAVBAR ACTIVE LINK
// =====================================

const sections = document.querySelectorAll("section");

const navLinks = document.querySelectorAll(".nav-links a");

window.addEventListener("scroll", () => {

    let current = "";

    sections.forEach(section => {

        const top = section.offsetTop - 120;

        if (window.pageYOffset >= top) {

            current = section.getAttribute("id");

        }

    });

    navLinks.forEach(link => {

        link.classList.remove("active");

        if (link.getAttribute("href") === "#" + current) {

            link.classList.add("active");

        }

    });

});

// =====================================
// BUTTON RIPPLE EFFECT
// =====================================

const buttons = document.querySelectorAll("button,.primary-btn,.scan-btn");

buttons.forEach(btn => {

    btn.addEventListener("click", function (e) {

        const circle = document.createElement("span");

        circle.classList.add("ripple");

        this.appendChild(circle);

        const x = e.clientX - this.offsetLeft;

        const y = e.clientY - this.offsetTop;

        circle.style.left = x + "px";

        circle.style.top = y + "px";

        setTimeout(() => {

            circle.remove();

        }, 600);

    });

});
// =====================================
// PHISHGUARD THREAT SCORE GAUGE
// =====================================

document.addEventListener("DOMContentLoaded", function () {

    const gauge =
        document.getElementById("gaugeProgress");

    const dot =
        document.getElementById("gaugeDot");

    const scoreText =
        document.getElementById("gaugeScore");

    const resultText =
        document.getElementById("gaugeResult");

    const riskText =
        document.getElementById("gaugeRisk");


    if (
        !gauge ||
        !dot ||
        !scoreText ||
        !resultText ||
        !riskText
    ) {
        return;
    }


    // =====================================
    // GET ML VALUES
    // =====================================

    const safeValue =
        Number(window.safeValue || 0);

    const phishingValue =
        Number(window.phishingValue || 0);


    // =====================================
    // GET FLASK PREDICTION
    // =====================================

    const prediction =
        String(window.prediction || "")
            .trim()
            .toLowerCase();


    // =====================================
    // CHECK PREDICTION
    // =====================================

    const isPhishing =
        prediction.includes("phishing");


    const isSafe =
        prediction.includes("safe");


    // =====================================
    // SELECT SCORE
    // =====================================

    let score = 0;


    if (isPhishing) {

        score = phishingValue;

    }

    else if (isSafe) {

        score = safeValue;

    }

    else {

        score =
            Math.max(
                safeValue,
                phishingValue
            );

    }


    score =
        Math.max(
            0,
            Math.min(100, score)
        );


    // =====================================
    // RESULT + RISK
    // =====================================

    if (isPhishing) {

        // 🔴 PHISHING

        resultText.innerText =
            "PHISHING";

        riskText.innerText =
            "Risk Level: HIGH";

        gauge.style.stroke =
            "#e53935";

        dot.style.fill =
            "#e53935";

        scoreText.style.color =
            "#e53935";

        resultText.style.color =
            "#e53935";

    }

    else {

        // 🟢 SAFE

        resultText.innerText =
            "SAFE";

        riskText.innerText =
            "Risk Level: LOW";

        gauge.style.stroke =
            "#00a86b";

        dot.style.fill =
            "#00a86b";

        scoreText.style.color =
            "#00a86b";

        resultText.style.color =
            "#00a86b";

    }


    // =====================================
    // GAUGE LENGTH
    // =====================================

    const totalLength =
        gauge.getTotalLength();


    // Start empty

    gauge.style.strokeDasharray =
        "0 100";


    // =====================================
    // ANIMATION
    // =====================================

    const duration = 2000;

    const startTime =
        performance.now();


    function animateGauge(currentTime) {

        const elapsed =
            currentTime - startTime;


        let progress =
            elapsed / duration;


        progress =
            Math.min(
                progress,
                1
            );


        // Smooth animation

        const eased =
            1 -
            Math.pow(
                1 - progress,
                3
            );


        const currentScore =
            score * eased;


        // =================================
        // DRAW LINE
        // =================================

        gauge.style.strokeDasharray =
            `${currentScore} 100`;


        // =================================
        // MOVE DOT ON EXACT LINE
        // =================================

        const currentLength =
            totalLength *
            (currentScore / 100);


        const point =
            gauge.getPointAtLength(
                currentLength
            );


        dot.setAttribute(
            "cx",
            point.x
        );


        dot.setAttribute(
            "cy",
            point.y
        );


        dot.style.opacity =
            "1";


        if (progress < 1) {

            requestAnimationFrame(
                animateGauge
            );

        }

    }


    requestAnimationFrame(
        animateGauge
    );


    // =====================================
    // NUMBER ANIMATION
    // =====================================

    let current = 0;


    const numberAnimation =
        setInterval(function () {

            current += 1;


            if (current >= score) {

                current = score;

                clearInterval(
                    numberAnimation
                );

            }


            scoreText.innerText =
                current.toFixed(2) + "%";


        }, 15);


});