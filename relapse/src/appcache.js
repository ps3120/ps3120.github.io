function registerAppCacheEventHandlers() {
  const appCache = window.applicationCache;
  if (!appCache) return;

  function log(message, type = "log") {
    if (typeof window.writeLog === "function") window.writeLog(message, type);
  }

  appCache.addEventListener("downloading", () =>
    log("appcache: downloading updates", "info"), false);
  appCache.addEventListener("cached", () =>
    log("appcache: saved, offline use is available", "success"), false);
  appCache.addEventListener("noupdate", () =>
    log("appcache: up to date", "info"), false);
  appCache.addEventListener("updateready", () => {
    if (appCache.status !== appCache.UPDATEREADY) return;
    appCache.swapCache();
    log("appcache: updated, reload to apply", "info");
  }, false);
  appCache.addEventListener("error", () =>
    log("appcache: update failed", "error"), false);
}

if (window.applicationCache) registerAppCacheEventHandlers();
