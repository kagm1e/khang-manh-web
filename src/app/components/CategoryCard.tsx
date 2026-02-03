import { motion } from 'motion/react';
import { LucideIcon } from 'lucide-react';
import { useRef } from 'react';
import { useScrollAnimation } from '@/app/hooks/useScrollAnimation';

interface CategoryCardProps {
  title: string;
  description: string;
  count: number;
  icon: LucideIcon;
  color: string;
}

export function CategoryCard({ title, description, count, icon: Icon, color }: CategoryCardProps) {
  const cardRef = useRef<HTMLDivElement>(null);
  const isVisible = useScrollAnimation(cardRef);

  return (
    <motion.div
      ref={cardRef}
      className="relative group cursor-pointer"
      initial={{ opacity: 0, y: 50 }}
      animate={{ 
        opacity: isVisible ? 1 : 0,
        y: isVisible ? 0 : 50
      }}
      transition={{ duration: 0.6, ease: 'easeOut' }}
      whileHover={{ y: -8 }}
    >
      {/* Gradient border animation container */}
      <div className="absolute inset-0 rounded-2xl opacity-0 group-hover:opacity-100 transition-opacity duration-300">
        <div 
          className="absolute inset-0 rounded-2xl animate-gradient-rotate"
          style={{
            background: `linear-gradient(90deg, ${color}, #06b6d4, #10b981, ${color})`,
            backgroundSize: '300% 300%',
            padding: '2px',
            WebkitMask: 'linear-gradient(#fff 0 0) content-box, linear-gradient(#fff 0 0)',
            WebkitMaskComposite: 'xor',
            maskComposite: 'exclude',
          }}
        />
      </div>

      {/* Card content */}
      <div className="relative bg-white dark:bg-gray-800 rounded-2xl p-6 shadow-sm hover:shadow-xl transition-all duration-300 border-2 border-gray-100 dark:border-gray-700 hover:border-cyan-500 dark:hover:border-cyan-500 h-full">
        <div className="flex items-start justify-between mb-4">
          <div className={`p-3 rounded-lg`} style={{ backgroundColor: `${color}15` }}>
            <Icon className="w-6 h-6" style={{ color }} />
          </div>
          <motion.div
            className="text-2xl font-semibold text-gray-800 dark:text-white"
            whileHover={{ scale: 1.15 }}
            transition={{ type: 'spring', stiffness: 300 }}
          >
            {count}
          </motion.div>
        </div>
        
        <h3 className="text-xl font-semibold text-gray-900 dark:text-white mb-2">{title}</h3>
        <p className="text-gray-600 dark:text-gray-400 text-sm leading-relaxed">{description}</p>
      </div>

      {/* Add keyframe animation to CSS */}
      <style>{`
        @keyframes gradient-rotate {
          0% {
            background-position: 0% 50%;
          }
          50% {
            background-position: 100% 50%;
          }
          100% {
            background-position: 0% 50%;
          }
        }
        .animate-gradient-rotate {
          animation: gradient-rotate 3s ease infinite;
        }
      `}</style>
    </motion.div>
  );
}