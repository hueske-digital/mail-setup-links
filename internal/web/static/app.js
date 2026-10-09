const status = document.getElementById("status");

// iPads send a Mac user agent. A "Mac" with a touch screen gets the iPhone and iPad
// recommendation instead.
const recommended = document.querySelector('.tiles > .is-recommended[data-client="mac"]');
const touchDevice = document.querySelector('.tiles > [data-client="iphone"]');
if (recommended && touchDevice && navigator.maxTouchPoints > 1) {
  recommended.classList.remove("is-recommended");
  touchDevice.classList.add("is-recommended");
  touchDevice.querySelector(".tile-text").prepend(recommended.querySelector(".badge"));
  touchDevice.parentElement.prepend(touchDevice);
}

// The clipboard API only exists in secure contexts; without it the copy buttons stay hidden.
const buttons = navigator.clipboard ? document.querySelectorAll("[data-copy]") : [];

for (const button of buttons) {
  const label = button.textContent;
  button.hidden = false;
  button.addEventListener("click", () => {
    navigator.clipboard.writeText(button.dataset.copy).then(
      () => {
        button.textContent = "Kopiert";
        status.textContent = "In die Zwischenablage kopiert.";
        setTimeout(() => {
          button.textContent = label;
          status.textContent = "";
        }, 2000);
      },
      () => {
        status.textContent = "Kopieren nicht möglich – bitte den Text markieren und manuell kopieren.";
      },
    );
  });
}
