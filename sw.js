self.addEventListener("push", function (event) {
  var data = {};
  try {
    data = event.data ? event.data.json() : {};
  } catch (e) {
    data = {
      title: "Notification",
      body: event.data && event.data.text ? event.data.text() : "",
      url: "http://127.0.0.1:5000/info/",
    };
  }
  var title = data.title || "Notification";
  var options = {
    body: data.body || "",
    data: { url: data.url || "http://127.0.0.1:5000/info/" },
  };
  event.waitUntil(self.registration.showNotification(title, options));
});

self.addEventListener("notificationclick", function (event) {
  event.notification.close();
  var url = (event.notification.data && event.notification.data.url) || "http://127.0.0.1:5000/info/";
  event.waitUntil(clients.openWindow(url));
});
