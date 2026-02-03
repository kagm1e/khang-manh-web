import React, { useEffect, useRef } from 'react';

export function ParticleBackground() {
  const canvasRef = useRef<HTMLCanvasElement>(null);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;

    const ctx = canvas.getContext('2d');
    if (!ctx) return;

    let animationFrameId: number;

    const resizeCanvas = () => {
      canvas.width = window.innerWidth;
      canvas.height = window.innerHeight;
    };

    window.addEventListener('resize', resizeCanvas);
    resizeCanvas();

    // Cấu hình các dãy số nhị phân
    const fontSize = 16;
    const columns = Math.floor(canvas.width / fontSize);
    const drops: number[] = new Array(columns).fill(1);
    const binary = "01";

    const draw = () => {
      // Tạo hiệu ứng mờ dần để tạo đuôi cho các con số
      ctx.fillStyle = 'rgba(10, 10, 12, 0.1)'; 
      ctx.fillRect(0, 0, canvas.width, canvas.height);

      // Thiết lập màu sắc cho chữ (màu xanh Cyan đặc trưng)
      ctx.fillStyle = '#06b6d4';
      ctx.font = `${fontSize}px monospace`;

      for (let i = 0; i < drops.length; i++) {
        const text = binary.charAt(Math.floor(Math.random() * binary.length));
        ctx.fillText(text, i * fontSize, drops[i] * fontSize);

        // Reset dòng khi chạm đáy hoặc ngẫu nhiên
        if (drops[i] * fontSize > canvas.height && Math.random() > 0.975) {
          drops[i] = 0;
        }
        drops[i]++;
      }
      animationFrameId = requestAnimationFrame(draw);
    };

    draw();

    return () => {
      window.removeEventListener('resize', resizeCanvas);
      cancelAnimationFrame(animationFrameId);
    };
  }, []);

  return (
    <canvas
      ref={canvasRef}
      className="fixed top-0 left-0 w-full h-full pointer-events-none opacity-[0.15] dark:opacity-[0.25]"
      style={{ zIndex: 0 }}
    />
  );
}