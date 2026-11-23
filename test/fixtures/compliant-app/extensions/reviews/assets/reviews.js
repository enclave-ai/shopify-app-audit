const container = document.getElementById("reviews");
fetch(`https://api.reviewsdemo.io/reviews?product_id=${container.dataset.productId}`)
  .then((r) => r.json())
  .then((reviews) => {
    container.textContent = `${reviews.length} reviews`;
  });
