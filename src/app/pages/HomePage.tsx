import { motion } from 'motion/react';
import { 
  FileText, 
  Search, 
  Bug, 
  Cloud,
  Github,
  Instagram,
  Send,
  BookOpen,
  Award as AwardIcon,
  Users,
  Shield
} from 'lucide-react';
import { CategoryCard } from '@/app/components/CategoryCard';
import { Link } from 'react-router-dom';

export function HomePage() {
  const categories = [
    {
      title: 'Official Write-up',
      description: 'Official writeups from CTF competitions and challenges',
      count: 24,
      icon: FileText,
      color: '#06b6d4', // cyan
      slug: 'official-writeup',
    },
    {
      title: 'DFIR',
      description: 'Digital Forensics & Incident Response',
      count: 18,
      icon: Search,
      color: '#8b5cf6', // purple
      slug: 'dfir',
    },
    {
      title: 'Malware, SOC, Cloud',
      description: 'Malware analysis, Security Operations Center, Cloud Security',
      count: 15,
      icon: Bug,
      color: '#ef4444', // red
      slug: 'malware-analysis',
    },
    {
      title: 'Others',
      description: 'Other Categories: Crypto, Pwn, Reverse Engineering',
      count: 21,
      icon: Cloud,
      color: '#10b981', // green
      slug: 'soc-cloud-others',
    },
  ];

  const stats = [
    { label: 'Total Writeups', value: '78', icon: BookOpen },
    { label: 'CTF Participated', value: '35', icon: AwardIcon },
    { label: 'Views', value: '782', icon: Users },
  ];

  const scrollToCategories = () => {
    const categoriesSection = document.getElementById('categories-section');
    if (categoriesSection) {
      categoriesSection.scrollIntoView({ behavior: 'smooth', block: 'start' });
    }
  };

  return (
    <>
      {/* Hero Section */}
      <section className="max-w-7xl mx-auto px-6 py-20">
        <div className="text-center">
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.6 }}
          >
            <h1 className="text-7xl font-bold text-gray-900 dark:text-white mb-4">
              Le Manh Khang
            </h1>
            <div className="flex items-center justify-center gap-2 text-xl text-gray-600 dark:text-gray-300 mb-2">
              <Shield className="w-5 h-5 text-cyan-500" />
              <p>Military Technical Academy</p>
            </div>
            <p className="text-lg text-gray-500 dark:text-gray-400 mb-8">
              Cybersecurity Researcher • Blue Team Player • Writeup Author
            </p>
          </motion.div>

          {/* Social Links */}
          <motion.div
            className="flex items-center justify-center gap-4 mb-12"
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.2, duration: 0.6 }}
          >
            <motion.a
              href="https://github.com/kagm1e"
              target="_blank"
              rel="noopener noreferrer"
              className="p-3 rounded-lg bg-white dark:bg-gray-800 shadow-md hover:shadow-xl transition-all duration-300 group"
              whileHover={{ scale: 1.1, y: -2 }}
              whileTap={{ scale: 0.95 }}
            >
              <Github className="w-6 h-6 text-gray-700 dark:text-gray-300 group-hover:text-black dark:group-hover:text-white transition-colors" />
            </motion.a>

            <motion.a
              href="https://www.instagram.com/kagmle.ils/"
              target="_blank"
              rel="noopener noreferrer"
              className="p-3 rounded-lg bg-white dark:bg-gray-800 shadow-md hover:shadow-xl transition-all duration-300 group relative overflow-hidden"
              whileHover={{ scale: 1.1, y: -2 }}
              whileTap={{ scale: 0.95 }}
            >
              <div className="absolute inset-0 bg-gradient-to-br from-purple-500 via-pink-500 to-orange-500 opacity-0 group-hover:opacity-100 transition-opacity duration-300" />
              <Instagram className="w-6 h-6 text-gray-700 dark:text-gray-300 group-hover:text-white relative z-10 transition-colors" />
            </motion.a>

            <motion.a
  href="https://t.me/kagmle757"
  target="_blank"
  rel="noopener noreferrer"
  className="p-3 rounded-lg bg-white dark:bg-gray-800 shadow-md hover:shadow-xl transition-all duration-300 group"
  whileHover={{ scale: 1.1, y: -2 }}
  whileTap={{ scale: 0.95 }}
>
  {/* Thay MessageCircle bằng Send để hiện logo Telegram chuyên nghiệp */}
  <Send className="w-6 h-6 text-gray-700 dark:text-gray-300 group-hover:text-[#229ED9] dark:group-hover:text-[#229ED9] transition-colors" />
</motion.a>
          </motion.div>
        </div>
      </section>

      {/* Categories Section */}
      <section id="categories-section" className="max-w-7xl mx-auto px-6 pt-24 pb-16">
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          whileInView={{ opacity: 1, y: 0 }}
          viewport={{ once: true }}
          transition={{ duration: 0.6 }}
          className="mb-12"
        >
          <h2 className="text-4xl font-bold text-gray-900 dark:text-white mb-4">Categories</h2>
        </motion.div>

        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
          {categories.map((category, index) => (
            <Link key={category.title} to={`/category/${category.slug}`}>
              <div style={{ transitionDelay: `${index * 100}ms` }}>
                <CategoryCard {...category} />
              </div>
            </Link>
          ))}
        </div>
      </section>

      {/* Stats Section */}
      <section className="max-w-7xl mx-auto px-6 py-16">
        <div className="bg-white dark:bg-gray-800 rounded-3xl shadow-xl p-12">
          <div className="grid grid-cols-1 md:grid-cols-3 gap-8">
            {stats.map((stat, index) => (
              <motion.div
                key={stat.label}
                className="text-center"
                initial={{ opacity: 0, scale: 0.8 }}
                whileInView={{ opacity: 1, scale: 1 }}
                viewport={{ once: true }}
                transition={{ delay: index * 0.1, duration: 0.5 }}
                whileHover={{ y: -5 }}
              >
                <div className="flex justify-center mb-4">
                  <div className="p-4 bg-gradient-to-br from-cyan-500 to-blue-500 rounded-2xl">
                    <stat.icon className="w-8 h-8 text-white" />
                  </div>
                </div>
                <div className="text-4xl font-bold text-gray-900 dark:text-white mb-2">{stat.value}</div>
                <div className="text-gray-600 dark:text-gray-400">{stat.label}</div>
              </motion.div>
            ))}
          </div>
        </div>
      </section>
    </>
  );
}
