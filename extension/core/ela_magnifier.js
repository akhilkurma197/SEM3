/**
 * Trust Layer - Interactive ELA Heatmap Split Slider & 4x Magnifying Lens
 */

export class ELAMagnifier {
  /**
   * Attach split-view comparison slider & 4x magnifying lens to target container
   * @param {HTMLElement} containerEl 
   * @param {HTMLImageElement|string} originalImg 
   * @param {HTMLCanvasElement} elaCanvas 
   */
  static initSplitSliderAndLens(containerEl, originalImgSrc, elaCanvas) {
    if (!containerEl) return;
    containerEl.innerHTML = '';

    const wrapper = document.createElement('div');
    wrapper.className = 'ela-split-wrapper';
    wrapper.style.cssText = `
      position: relative;
      width: 100%;
      height: 380px;
      background: #000;
      border-radius: 12px;
      overflow: hidden;
      border: 1px solid rgba(255, 255, 255, 0.15);
      user-select: none;
      cursor: crosshair;
    `;

    // 1. Original Image Layer
    const origLayer = document.createElement('div');
    origLayer.className = 'ela-layer original-layer';
    origLayer.style.cssText = `
      position: absolute;
      top: 0; left: 0; width: 100%; height: 100%;
      background-image: url('${typeof originalImgSrc === 'string' ? originalImgSrc : originalImgSrc.src}');
      background-size: contain;
      background-position: center;
      background-repeat: no-repeat;
    `;

    // 2. ELA Differential Layer (Clipped by Slider)
    const elaLayer = document.createElement('div');
    elaLayer.className = 'ela-layer differential-layer';
    elaLayer.style.cssText = `
      position: absolute;
      top: 0; left: 0; width: 50%; height: 100%;
      overflow: hidden;
      border-right: 2px solid #06b6d4;
      box-shadow: 2px 0 15px rgba(6, 182, 212, 0.6);
    `;

    const elaImg = document.createElement('img');
    elaImg.src = elaCanvas ? elaCanvas.toDataURL() : originalImgSrc;
    elaImg.style.cssText = `
      height: 100%;
      width: auto;
      min-width: 100%;
      object-fit: contain;
      object-position: center;
    `;
    elaLayer.appendChild(elaImg);

    // 3. Slider Handle Divider
    const sliderHandle = document.createElement('div');
    sliderHandle.className = 'ela-slider-handle';
    sliderHandle.style.cssText = `
      position: absolute;
      top: 0; left: 50%; height: 100%; width: 4px;
      background: #06b6d4;
      z-index: 10;
      transform: translateX(-50%);
      pointer-events: none;
    `;
    sliderHandle.innerHTML = `
      <div style="
        position: absolute; top: 50%; left: 50%; transform: translate(-50%, -50%);
        width: 32px; height: 32px; background: #06b6d4; border-radius: 50%;
        display: flex; align-items: center; justify-content: center;
        color: #fff; font-size: 12px; font-weight: 700; box-shadow: 0 0 15px rgba(6,182,212,0.8);
      ">↔</div>
    `;

    // 4. 4x Magnifying Lens Circle
    const lens = document.createElement('div');
    lens.className = 'ela-magnify-lens';
    lens.style.cssText = `
      position: absolute;
      width: 120px;
      height: 120px;
      border-radius: 50%;
      border: 3px solid #f43f5e;
      box-shadow: 0 0 20px rgba(244, 63, 94, 0.6), inset 0 0 15px rgba(0,0,0,0.8);
      pointer-events: none;
      display: none;
      z-index: 20;
      background-repeat: no-repeat;
      background-size: 400%; /* 4x Zoom */
    `;

    wrapper.appendChild(origLayer);
    wrapper.appendChild(elaLayer);
    wrapper.appendChild(sliderHandle);
    wrapper.appendChild(lens);
    containerEl.appendChild(wrapper);

    // Drag & Move Event Listeners for Split Slider
    let isDragging = false;

    const updateSlider = (clientX) => {
      const rect = wrapper.getBoundingClientRect();
      let offsetX = clientX - rect.left;
      offsetX = Math.max(0, Math.min(offsetX, rect.width));
      const pct = (offsetX / rect.width) * 100;

      elaLayer.style.width = `${pct}%`;
      sliderHandle.style.left = `${pct}%`;
    };

    wrapper.addEventListener('mousedown', (e) => {
      isDragging = true;
      updateSlider(e.clientX);
    });

    window.addEventListener('mousemove', (e) => {
      if (isDragging) updateSlider(e.clientX);

      // Update 4x Lens Position & Zoom Background
      const rect = wrapper.getBoundingClientRect();
      if (e.clientX >= rect.left && e.clientX <= rect.right && e.clientY >= rect.top && e.clientY <= rect.bottom) {
        lens.style.display = 'block';
        const relX = e.clientX - rect.left;
        const relY = e.clientY - rect.top;

        lens.style.left = `${relX - 60}px`;
        lens.style.top = `${relY - 60}px`;

        // 4x Zoom background calculations
        const bgX = (relX / rect.width) * 100;
        const bgY = (relY / rect.height) * 100;
        lens.style.backgroundImage = `url('${elaImg.src}')`;
        lens.style.backgroundPosition = `${bgX}% ${bgY}%`;
      } else {
        lens.style.display = 'none';
      }
    });

    window.addEventListener('mouseup', () => { isDragging = false; });
  }
}
