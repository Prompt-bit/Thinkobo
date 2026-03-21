(function () {
  function initVideoPromo(root) {
    const video = root.querySelector("[data-video]");
    const shell = root.querySelector("[data-video-shell]");
    const bigBtn = root.querySelector("[data-big-btn]");
    const bigPlay = root.querySelector("[data-big-play]");
    const bigPause = root.querySelector("[data-big-pause]");
    const miniBtn = root.querySelector("[data-mini-btn]");
    const miniPlay = root.querySelector("[data-mini-play]");
    const miniPause = root.querySelector("[data-mini-pause]");
    const progress = root.querySelector("[data-progress]");
    const volume = root.querySelector("[data-volume]");
    const timeLabel = root.querySelector("[data-time]");

    if (
      !video ||
      !shell ||
      !bigBtn ||
      !bigPlay ||
      !bigPause ||
      !miniBtn ||
      !miniPlay ||
      !miniPause ||
      !progress ||
      !timeLabel
    ) {
      return;
    }

    const clamp01 = (n) => Math.max(0, Math.min(1, n));
    const clamp100 = (n) => Math.max(0, Math.min(100, n));

    function formatTime(seconds) {
      if (!Number.isFinite(seconds) || seconds < 0) return "0:00";
      const m = Math.floor(seconds / 60);
      const s = Math.floor(seconds % 60);
      return `${m}:${String(s).padStart(2, "0")}`;
    }

    function setRangeGradient(el, percent) {
      const p = Math.max(0, Math.min(100, percent));
      el.style.background = `linear-gradient(to right, rgb(99, 102, 241) 0%, rgb(99, 102, 241) ${p}%, rgba(255,255,255,0.25) ${p}%, rgba(255,255,255,0.25) 100%)`;
    }

    function setProgressUI(percent) {
      const p = Math.max(0, Math.min(100, percent));
      progress.value = String(p);
      setRangeGradient(progress, p);
    }

    function syncUI() {
      const isPlaying = !video.paused && !video.ended;
      bigPlay.classList.toggle("hidden", isPlaying);
      bigPause.classList.toggle("hidden", !isPlaying);
      miniPlay.classList.toggle("hidden", isPlaying);
      miniPause.classList.toggle("hidden", !isPlaying);
      miniBtn.setAttribute("aria-label", isPlaying ? "Pause" : "Play");
      bigBtn.setAttribute("aria-label", isPlaying ? "Pause" : "Play");

      const duration = video.duration || 0;
      const current = video.currentTime || 0;
      const percent = duration ? (current / duration) * 100 : 0;
      setProgressUI(percent);
      timeLabel.textContent = `${formatTime(current)} / ${formatTime(duration)}`;

      bigBtn.classList.toggle("opacity-0", isPlaying);
      bigBtn.classList.toggle("pointer-events-none", isPlaying);
    }

    function togglePlay() {
      if (video.paused || video.ended) video.play();
      else video.pause();
    }

    bigBtn.addEventListener("click", togglePlay);
    miniBtn.addEventListener("click", togglePlay);
    video.addEventListener("click", togglePlay);

    shell.addEventListener("keydown", (e) => {
      if (e.code === "Space" || e.code === "Enter") {
        e.preventDefault();
        togglePlay();
      }
    });

    progress.addEventListener("input", () => {
      const duration = video.duration || 0;
      if (!duration) return;
      const pct = clamp01(Number(progress.value) / 100);
      video.currentTime = pct * duration;
      syncUI();
    });

    if (volume) {
      function syncVolumeUI() {
        const v = Number.isFinite(video.volume) ? video.volume : 1;
        const pct = clamp100(Math.round(v * 100));
        volume.value = String(pct);
        setRangeGradient(volume, pct);
      }

      volume.addEventListener("input", () => {
        const pct = clamp100(Number(volume.value));
        video.muted = pct === 0;
        video.volume = pct / 100;
        syncVolumeUI();
      });

      video.addEventListener("volumechange", syncVolumeUI);
      syncVolumeUI();
    }

    video.addEventListener("loadedmetadata", syncUI);
    video.addEventListener("timeupdate", syncUI);
    video.addEventListener("play", syncUI);
    video.addEventListener("pause", syncUI);
    video.addEventListener("ended", syncUI);

    syncUI();
  }

  function initAll() {
    document.querySelectorAll("[data-video-promo]").forEach(initVideoPromo);
  }

  window.ThinkoboVideoPromo = { init: initVideoPromo, initAll };

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", initAll);
  } else {
    initAll();
  }
})();
