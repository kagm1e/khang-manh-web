import { motion } from 'motion/react';
import { useParams, Link } from 'react-router-dom';
import { ArrowLeft, Calendar, Clock, Tag, ChevronRight } from 'lucide-react';
import { useEffect, useState } from 'react';
import ReactMarkdown from 'react-markdown';
import remarkGfm from 'remark-gfm';

export function WriteupPage() {
  const { category, id } = useParams<{ category: string; id: string }>();
  const [markdown, setMarkdown] = useState('');
  const [loading, setLoading] = useState(true);

  // Mock data for metadata - this could be fetched alongside the markdown in a real app
  const writeupMeta = {
    title: id?.replace(/-/g, ' ').replace(/\b\w/g, (l) => l.toUpperCase()) || 'Writeup',
    date: '2025-01-28',
    readTime: '8 min',
    difficulty: 'Medium',
    tags: ['Web Security', 'CTF'],
  };

  useEffect(() => {
    setLoading(true);
    fetch(`/writeups/${id}.md`)
      .then((response) => {
        if (!response.ok) {
          throw new Error('Network response was not ok');
        }
        return response.text();
      })
      .then((text) => {
        setMarkdown(text);
        setLoading(false);
      })
      .catch((error) => {
        console.error("Error fetching markdown:", error);
        setMarkdown(`# Error\n\nCould not load the writeup. Please check the console for details.`);
        setLoading(false);
      });
  }, [id]);

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

  return (
    <div className="min-h-screen bg-[#f4f4f4] dark:bg-gray-900 pt-20">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 py-8">
        <Link to={`/category/${category}`}>
          <motion.button
            className="flex items-center gap-2 text-gray-600 dark:text-gray-300 hover:text-cyan-500 dark:hover:text-cyan-400 mb-8"
            whileHover={{ x: -5 }}
            transition={{ duration: 0.2 }}
          >
            <ArrowLeft className="w-5 h-5" />
            <span className="hidden sm:inline">Back to Category</span>
            <span className="sm:hidden">Back</span>
          </motion.button>
        </Link>

        <main>
          <motion.article
            className="bg-white dark:bg-gray-800 rounded-2xl p-6 sm:p-8 shadow-xl"
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.6 }}
          >
            <header className="mb-8 pb-8 border-b border-gray-200 dark:border-gray-700">
              <h1 className="text-3xl sm:text-4xl font-bold text-gray-900 dark:text-white mb-4">
                {writeupMeta.title}
              </h1>
              <div className="flex flex-wrap items-center gap-3 sm:gap-4 text-sm text-gray-600 dark:text-gray-400 mb-4">
                <div className="flex items-center gap-2">
                  <Calendar className="w-4 h-4" />
                  <span>{writeupMeta.date}</span>
                </div>
                <div className="flex items-center gap-2">
                  <Clock className="w-4 h-4" />
                  <span>{writeupMeta.readTime} read</span>
                </div>
                <span
                  className={`px-3 py-1 rounded-full text-xs font-semibold ${getDifficultyColor(
                    writeupMeta.difficulty
                  )}`}
                >
                  {writeupMeta.difficulty}
                </span>
              </div>
              <div className="flex flex-wrap items-center gap-2">
                <Tag className="w-4 h-4 text-gray-400" />
                {writeupMeta.tags.map((tag, i) => (
                  <span
                    key={i}
                    className="px-3 py-1 bg-gray-100 dark:bg-gray-700 text-gray-700 dark:text-gray-300 rounded-full text-xs"
                  >
                    {tag}
                  </span>
                ))}
              </div>
            </header>

            {loading ? (
              <div className="prose prose-lg dark:prose-invert max-w-none">
                <p>Loading...</p>
              </div>
            ) : (
              <div className="prose prose-slate dark:prose-invert max-w-none prose-h1:text-3xl prose-h2:text-2xl prose-h3:text-xl prose-a:text-cyan-600 dark:prose-a:text-cyan-400 hover:prose-a:underline prose-pre:bg-gray-100 dark:prose-pre:bg-gray-900 prose-pre:p-4 prose-pre:rounded-lg">
                <ReactMarkdown remarkPlugins={[remarkGfm]}>{markdown}</ReactMarkdown>
              </div>
            )}
          </motion.article>
        </main>
      </div>
    </div>
  );
}
