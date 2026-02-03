import { useState, useEffect, RefObject } from 'react';

export function useScrollAnimation(ref: RefObject<HTMLElement>, threshold = 0.1) {
  const [isVisible, setIsVisible] = useState(false);

  useEffect(() => {
    const observer = new IntersectionObserver(
      ([entry]) => {
        // Nếu phần tử bắt đầu đi vào tầm mắt (viewport)
        if (entry.isIntersecting) {
          setIsVisible(true);
          // Sau khi đã hiện lên thì ngừng quan sát để tối ưu hiệu năng
          if (ref.current) {
            observer.unobserve(ref.current);
          }
        }
      },
      {
        threshold, // Tỷ lệ phần tử xuất hiện (0.1 = 10%)
      }
    );

    const currentRef = ref.current;
    if (currentRef) {
      observer.observe(currentRef);
    }

    return () => {
      if (currentRef) {
        observer.unobserve(currentRef);
      }
    };
  }, [ref, threshold]);

  return isVisible;
}