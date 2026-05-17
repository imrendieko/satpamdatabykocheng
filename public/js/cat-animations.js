// Cat animations and interactions

class CatAnimationManager {
  constructor() {
    this.cats = ['🐱', '😺', '😸', '😹', '😻', '😼', '😽', '🙀', '😿', '😾'];
    this.particles = [];
    this.init();
  }

  init() {
    this.createBackgroundCats();
    this.startParticleSystem();
    this.addInteractionListeners();
  }

  createBackgroundCats() {
    const background = document.getElementById('cat-background');
    if (!background) return;

    // Create floating cat particles
    for (let i = 0; i < 15; i++) {
      const particle = document.createElement('div');
      particle.className = 'cat-particle';
      particle.textContent = this.cats[Math.floor(Math.random() * this.cats.length)];
      particle.style.left = Math.random() * 100 + '%';
      particle.style.top = Math.random() * 100 + '%';
      particle.style.animationDelay = Math.random() * 5 + 's';
      particle.style.animationDuration = 3 + Math.random() * 4 + 's';
      particle.style.fontSize = 16 + Math.random() * 32 + 'px';
      background.appendChild(particle);
      this.particles.push(particle);
    }
  }

  startParticleSystem() {
    // Add new particles periodically
    setInterval(() => {
      this.createTemporaryParticle();
    }, 3000);
  }

  createTemporaryParticle() {
    const particle = document.createElement('div');
    particle.className = 'cat-particle';
    particle.textContent = this.cats[Math.floor(Math.random() * this.cats.length)];
    particle.style.left = Math.random() * 100 + '%';
    particle.style.top = '100%';
    particle.style.fontSize = 20 + Math.random() * 24 + 'px';

    document.body.appendChild(particle);

    // Animate upward
    setTimeout(() => {
      particle.style.transition = 'all 4s linear';
      particle.style.top = '-10%';
      particle.style.opacity = '0';
    }, 100);

    // Remove after animation
    setTimeout(() => {
      if (particle.parentNode) {
        particle.parentNode.removeChild(particle);
      }
    }, 4100);
  }

  addInteractionListeners() {
    // Make input fields interactive with cats
    document.addEventListener('focusin', (e) => {
      if (e.target.tagName === 'INPUT') {
        this.showCatNearElement(e.target, '😸');
      }
    });

    document.addEventListener('focusout', (e) => {
      if (e.target.tagName === 'INPUT') {
        this.showCatNearElement(e.target, '😴');
      }
    });

    // Add cat reactions to buttons
    document.querySelectorAll('button').forEach((button) => {
      button.addEventListener('mouseenter', () => {
        this.showCatReaction(button, '😻');
      });
      button.addEventListener('click', () => {
        this.showCatReaction(button, '😹', true);
      });
    });
  }

  showCatNearElement(element, cat) {
    const rect = element.getBoundingClientRect();
    const catEl = document.createElement('div');
    catEl.textContent = cat;
    catEl.style.cssText = `
            position: fixed;
            left: ${rect.right + 10}px;
            top: ${rect.top}px;
            font-size: 30px;
            pointer-events: none;
            z-index: 1000;
            transition: all 0.3s ease;
        `;

    document.body.appendChild(catEl);

    // Animate and remove
    setTimeout(() => {
      catEl.style.transform = 'scale(1.5)';
      catEl.style.opacity = '0';
    }, 100);

    setTimeout(() => {
      if (catEl.parentNode) {
        catEl.parentNode.removeChild(catEl);
      }
    }, 400);
  }

  showCatReaction(element, cat, isClick = false) {
    const rect = element.getBoundingClientRect();
    const catEl = document.createElement('div');
    catEl.textContent = cat;
    catEl.style.cssText = `
            position: fixed;
            left: ${rect.left + rect.width / 2 - 15}px;
            top: ${rect.top - 40}px;
            font-size: 30px;
            pointer-events: none;
            z-index: 1000;
            transition: all 0.5s ease;
        `;

    document.body.appendChild(catEl);

    if (isClick) {
      // Burst effect for clicks
      for (let i = 0; i < 5; i++) {
        setTimeout(() => {
          const burstCat = document.createElement('div');
          burstCat.textContent = this.cats[Math.floor(Math.random() * this.cats.length)];
          burstCat.style.cssText = `
                        position: fixed;
                        left: ${rect.left + rect.width / 2}px;
                        top: ${rect.top}px;
                        font-size: 20px;
                        pointer-events: none;
                        z-index: 999;
                        transition: all 1s ease-out;
                    `;
          document.body.appendChild(burstCat);

          const angle = (Math.PI * 2 * i) / 5;
          const velocity = 50;
          const dx = Math.cos(angle) * velocity;
          const dy = Math.sin(angle) * velocity;

          setTimeout(() => {
            burstCat.style.transform = `translate(${dx}px, ${dy}px)`;
            burstCat.style.opacity = '0';
          }, 50);

          setTimeout(() => {
            if (burstCat.parentNode) {
              burstCat.parentNode.removeChild(burstCat);
            }
          }, 1050);
        }, i * 50);
      }
    }

    // Remove main cat
    setTimeout(() => {
      catEl.style.transform = 'translateY(-20px)';
      catEl.style.opacity = '0';
    }, 500);

    setTimeout(() => {
      if (catEl.parentNode) {
        catEl.parentNode.removeChild(catEl);
      }
    }, 1000);
  }

  createScanningEffect() {
    const loadingSection = document.getElementById('loadingSection');
    if (!loadingSection) return;

    const catContainer = loadingSection.querySelector('.cat-scanner-animation');
    if (!catContainer) return;

    // Cycle through cat emojis during scanning
    const scanCats = ['🐱', '😺', '🔍', '😼', '🐱‍👤', '😸'];
    let index = 0;

    const interval = setInterval(() => {
      const catDiv = catContainer.querySelector('div:first-child');
      if (catDiv) {
        catDiv.textContent = scanCats[index];
        index = (index + 1) % scanCats.length;
      } else {
        clearInterval(interval);
      }
    }, 500);

    return interval;
  }

  showSuccessAnimation() {
    for (let i = 0; i < 10; i++) {
      setTimeout(() => {
        const cat = document.createElement('div');
        cat.textContent = '😻';
        cat.style.cssText = `
                    position: fixed;
                    left: ${Math.random() * 100}%;
                    top: 100%;
                    font-size: ${24 + Math.random() * 24}px;
                    pointer-events: none;
                    z-index: 1000;
                    transition: all 2s linear;
                `;
        document.body.appendChild(cat);

        setTimeout(() => {
          cat.style.top = '-10%';
          cat.style.left = `${Math.random() * 100}%`;
          cat.style.opacity = '0';
        }, 100);

        setTimeout(() => {
          if (cat.parentNode) {
            cat.parentNode.removeChild(cat);
          }
        }, 2100);
      }, i * 100);
    }
  }

  showErrorAnimation() {
    const mainContent = document.querySelector('main');
    if (mainContent) {
      mainContent.classList.add('error-shake');
      setTimeout(() => {
        mainContent.classList.remove('error-shake');
      }, 500);
    }
  }
}

// Initialize cat animations when DOM is ready
document.addEventListener('DOMContentLoaded', () => {
  window.catAnimations = new CatAnimationManager();
});
