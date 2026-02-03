import { useEffect, useRef, useState } from 'react';

interface BinaryDrop {
  x: number;
  y: number;
  speed: number;
  value: string;
  opacity: number;
}

export function BinaryRain() {
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const [isDark, setIsDark] = useState(true);

  useEffect(() => {
    // Check if dark mode is enabled
    const checkDarkMode = () => {
      setIsDark(document.documentElement.classList.contains('dark'));
    };

    checkDarkMode();

    // Watch for theme changes
    const observer = new MutationObserver(checkDarkMode);
    observer.observe(document.documentElement, {
      attributes: true,
      attributeFilter: ['class'],
    });

    return () => observer.disconnect();
  }, []);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;

    const ctx = canvas.getContext('2d');
    if (!ctx) return;

    // Set canvas size
    const setCanvasSize = () => {
      canvas.width = window.innerWidth;
      canvas.height = window.innerHeight;
    };
    setCanvasSize();
    window.addEventListener('resize', setCanvasSize);

    // Create binary drops
    const drops: BinaryDrop[] = [];
    const columnWidth = 20;
    const columns = Math.floor(canvas.width / columnWidth);

    // Initialize drops
    for (let i = 0; i < columns; i++) {
      drops.push({
        x: i * columnWidth,
        y: Math.random() * -canvas.height,
        speed: Math.random() * 2 + 1,
        value: Math.random() > 0.5 ? '1' : '0',
        opacity: Math.random() * 0.5 + 0.3,
      });
    }

    // Animation loop
    let animationFrameId: number;

    const animate = () => {
      // Fade effect
      ctx.fillStyle = isDark
        ? 'rgba(17, 24, 39, 0.05)' // dark mode: slower fade
        : 'rgba(244, 244, 244, 0.1)'; // light mode: faster fade
      ctx.fillRect(0, 0, canvas.width, canvas.height);

      // Update and draw drops
      ctx.font = '14px monospace';

      drops.forEach((drop) => {
        // Random binary value
        drop.value = Math.random() > 0.5 ? '1' : '0';

        // Color based on theme
        const baseColor = isDark ? '0, 255, 255' : '6, 182, 212'; // cyan
        ctx.fillStyle = `rgba(${baseColor}, ${drop.opacity})`;

        // Draw the character
        ctx.fillText(drop.value, drop.x, drop.y);

        // Move drop down
        drop.y += drop.speed;

        // Reset drop when it goes off screen
        if (drop.y > canvas.height) {
          drop.y = Math.random() * -100;
          drop.speed = Math.random() * 2 + 1;
          drop.opacity = Math.random() * 0.5 + 0.3;
        }
      });

      animationFrameId = requestAnimationFrame(animate);
    };

    animate();

    return () => {
      window.removeEventListener('resize', setCanvasSize);
      cancelAnimationFrame(animationFrameId);
    };
  }, [isDark]);

  return (
    <canvas
      ref={canvasRef}
      className="fixed inset-0 pointer-events-none"
      style={{ zIndex: 1 }}
    />
  );
}
