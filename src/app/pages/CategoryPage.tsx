import { motion } from 'motion/react';
import { useParams, Link } from 'react-router-dom';
import { FileText, Clock, Calendar, ArrowLeft } from 'lucide-react';
import { useState } from 'react';

interface Writeup {
  id: string;
  title: string;
  date: string;
  readTime: string;
  difficulty: 'Easy' | 'Medium' | 'Hard';
  tags: string[];
  year: string;
}

export function CategoryPage() {
  const { category } = useParams<{ category: string }>();
  const [selectedYear, setSelectedYear] = useState('2025');

  // Mock data - sẽ được thay thế bằng dữ liệu thực từ backend
  const writeups: Writeup[] = [
    {
      id: '1',
      title: 'SQL Injection in Login Form - CTF Challenge',
      date: '2025-01-28',
      readTime: '8 min',
      difficulty: 'Medium',
      tags: ['SQL Injection', 'Web Security', 'CTF'],
      year: '2025',
    },
    {
      id: '2',
      title: 'Exploiting Buffer Overflow Vulnerability',
      date: '2025-01-25',
      readTime: '12 min',
      difficulty: 'Hard',
      tags: ['Binary Exploitation', 'Buffer Overflow'],
      year: '2025',
    },
    {
      id: '3',
      title: 'XSS Attack Vector Analysis',
      date: '2025-01-20',
      readTime: '6 min',
      difficulty: 'Easy',
      tags: ['XSS', 'Web Security'],
      year: '2025',
    },
    {
      id: '4',
      title: 'Advanced ROP Chain Techniques',
      date: '2026-12-15',
      readTime: '15 min',
      difficulty: 'Hard',
      tags: ['ROP', 'Binary Exploitation'],
      year: '2026',
    },
    {
      id: '5',
      title: 'CSRF Token Bypass Methods',
      date: '2026-11-08',
      readTime: '7 min',
      difficulty: 'Medium',
      tags: ['CSRF', 'Web Security'],
      year: '2026',
    },
  ];

  const years = ['2025', '2026', '2027'];
  const filteredWriteups = writeups.filter((w) => w.year === selectedYear);

  const getDifficultyColor = (difficulty: string) => {
    switch (difficulty) {
      case 'Easy':
        return 'bg-green-100 text-green-700 dark:bg-green-900 dark:text-green-300';
      case 'Medium':
        return 'bg-yellow-100 text-yellow-700 dark:bg-yellow-900 dark:text-yellow-300';
      case 'Hard':
        return 'bg-red-100 text-red-700 dark:bg-red-900 dark:text-red-300';
      default:
        return 'bg-gray-100 text-gray-700 dark:bg-gray-700 dark:text-gray-300';
    }
  };

  const categoryTitle = category?.replace(/-/g, ' ').replace(/\b\w/g, (l) => l.toUpperCase()) || 'Category';

  return (
    <div className="min-h-screen bg-[#f4f4f4] dark:bg-gray-900 pt-20">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 py-8">
        {/* Back button */}
        <Link to="/">
          <motion.button
            className="flex items-center gap-2 text-gray-600 dark:text-gray-300 hover:text-cyan-500 dark:hover:text-cyan-400 mb-8"
            whileHover={{ x: -5 }}
            transition={{ duration: 0.2 }}
          >
            <ArrowLeft className="w-5 h-5" />
            <span className="hidden sm:inline">Back to Home</span>
            <span className="sm:hidden">Back</span>
          </motion.button>
        </Link>

        <div className="grid grid-cols-1 lg:grid-cols-5 gap-6 lg:gap-8">
          {/* Left: Timeline */}
          <aside className="lg:col-span-1">
            <motion.div
              className="bg-white dark:bg-gray-800 rounded-2xl p-4 sm:p-6 shadow-xl lg:sticky lg:top-24"
              initial={{ opacity: 0, x: -20 }}
              animate={{ opacity: 1, x: 0 }}
              transition={{ duration: 0.6 }}
            >
              <h3 className="text-lg sm:text-xl font-bold text-gray-900 dark:text-white mb-6">
                Timeline
              </h3>

              {/* Years */}
              <div className="space-y-3">
                {years.map((year, index) => {
                  const yearWriteups = writeups.filter((w) => w.year === year);
                  return (
                    <motion.button
                      key={year}
                      onClick={() => setSelectedYear(year)}
                      className={`w-full text-left transition-all duration-200 ${
                        selectedYear === year ? 'scale-105' : 'scale-100'
                      }`}
                      whileHover={{ scale: 1.05 }}
                      initial={{ opacity: 0, x: -20 }}
                      animate={{ opacity: 1, x: 0 }}
                      transition={{ delay: index * 0.1 }}
                    >
                      <div
                        className={`p-4 rounded-xl border-2 ${
                          selectedYear === year
                            ? 'bg-gradient-to-r from-cyan-500 to-blue-500 text-white border-transparent'
                            : 'bg-gray-50 dark:bg-gray-700 text-gray-700 dark:text-gray-300 border-gray-200 dark:border-gray-600'
                        }`}
                      >
                        <div className="flex items-center justify-between mb-1">
                          <span className="text-2xl font-bold">{year}</span>
                          {selectedYear === year && (
                            <div className="w-2 h-2 bg-white rounded-full animate-pulse" />
                          )}
                        </div>
                        <div className="text-sm opacity-80">
                          {yearWriteups.length} writeup{yearWriteups.length !== 1 ? 's' : ''}
                        </div>
                      </div>
                    </motion.button>
                  );
                })}
              </div>

              {/* Total count */}
              <div className="mt-6 pt-6 border-t border-gray-200 dark:border-gray-700">
                <div className="text-center">
                  <div className="text-3xl font-bold text-cyan-500 mb-1">{writeups.length}</div>
                  <div className="text-sm text-gray-600 dark:text-gray-400">Total Writeups</div>
                </div>
              </div>
            </motion.div>
          </aside>

          {/* Right: Content */}
          <main className="lg:col-span-4">
            {/* Header */}
            <motion.div
              className="bg-gradient-to-r from-cyan-500 to-blue-500 rounded-2xl p-6 sm:p-8 mb-6 sm:mb-8 text-white shadow-xl"
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.6 }}
            >
              <h1 className="text-3xl sm:text-4xl font-bold mb-4">{categoryTitle}</h1>
              <p className="text-cyan-100 text-base sm:text-lg">
                Explore all writeups from {selectedYear}
              </p>
            </motion.div>

            {/* Writeup List */}
            <div className="space-y-12">
              {filteredWriteups.length > 0 ? (
                filteredWriteups.map((writeup, index) => (
                  <Link key={writeup.id} to={`/category/${category}/writeup/${writeup.id}`}>
                    <motion.article
                      className="bg-white dark:bg-gray-800 rounded-2xl p-4 sm:p-6 shadow-lg hover:shadow-2xl transition-all duration-300 cursor-pointer border-2 border-transparent hover:border-cyan-500"
                      initial={{ opacity: 0, y: 20 }}
                      animate={{ opacity: 1, y: 0 }}
                      transition={{ delay: index * 0.1, duration: 0.5 }}
                      whileHover={{ y: -10 }}
                    >
                      <div className="flex flex-col sm:flex-row items-start gap-4 sm:gap-6">
                        {/* Icon */}
                        <div className="flex-shrink-0 w-12 h-12 bg-cyan-100 dark:bg-cyan-900 rounded-lg flex items-center justify-center">
                          <FileText className="w-6 h-6 text-cyan-500" />
                        </div>

                        {/* Content */}
                        <div className="flex-1 min-w-0">
                          <h2 className="text-lg sm:text-xl font-bold text-gray-900 dark:text-white mb-3 hover:text-cyan-500 dark:hover:text-cyan-400 transition-colors break-words">
                            {writeup.title}
                          </h2>

                          {/* Meta info */}
                          <div className="flex flex-wrap items-center gap-3 sm:gap-4 text-sm text-gray-600 dark:text-gray-400 mb-4">
                            <div className="flex items-center gap-2">
                              <Calendar className="w-4 h-4" />
                              <span>{writeup.date}</span>
                            </div>
                            <div className="flex items-center gap-2">
                              <Clock className="w-4 h-4" />
                              <span>{writeup.readTime}</span>
                            </div>
                            <span
                              className={`px-3 py-1 rounded-full text-xs font-semibold ${getDifficultyColor(
                                writeup.difficulty
                              )}`}
                            >
                              {writeup.difficulty}
                            </span>
                          </div>

                          {/* Tags */}
                          <div className="flex flex-wrap gap-2">
                            {writeup.tags.map((tag, i) => (
                              <span
                                key={i}
                                className="px-3 py-1 bg-gray-100 dark:bg-gray-700 text-gray-700 dark:text-gray-300 rounded-full text-xs"
                              >
                                {tag}
                              </span>
                            ))}
                          </div>
                        </div>
                      </div>
                    </motion.article>
                  </Link>
                ))
              ) : (
                <motion.div
                  className="bg-white dark:bg-gray-800 rounded-2xl p-8 sm:p-12 text-center"
                  initial={{ opacity: 0 }}
                  animate={{ opacity: 1 }}
                >
                  <FileText className="w-12 h-12 sm:w-16 sm:h-16 text-gray-400 mx-auto mb-4" />
                  <h3 className="text-lg sm:text-xl font-bold text-gray-900 dark:text-white mb-2">
                    No writeups in {selectedYear}
                  </h3>
                  <p className="text-sm sm:text-base text-gray-600 dark:text-gray-400">
                    Select another year to view writeups.
                  </p>
                </motion.div>
              )}
            </div>
          </main>
        </div>
      </div>
    </div>
  );
}