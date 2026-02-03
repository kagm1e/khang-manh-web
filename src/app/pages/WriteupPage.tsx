import { motion } from 'motion/react';
import { useParams, Link } from 'react-router-dom';
import { ArrowLeft, Calendar, Clock, Tag, ChevronRight } from 'lucide-react';
import { useEffect, useState } from 'react';

export function WriteupPage() {
  const { category, id } = useParams<{ category: string; id: string }>();
  const [activeSection, setActiveSection] = useState('');

  // Mock writeup data
  const writeup = {
    id: '1',
    title: 'SQL Injection in Login Form - CTF Challenge',
    date: '2024-01-28',
    readTime: '8 min',
    difficulty: 'Medium',
    tags: ['SQL Injection', 'Web Security', 'CTF'],
    content: `
# Overview

Trong challenge này, chúng ta sẽ khai thác lỗ hổng SQL Injection trong form đăng nhập để bypass authentication và lấy được flag.

## Challenge Description

Target: http://ctf.example.com/login

Nhiệm vụ: Tìm cách đăng nhập vào hệ thống mà không cần username và password hợp lệ.

# Reconnaissance

## Initial Analysis

Đầu tiên, ta thử với một số payload SQL Injection cơ bản:

\`\`\`
Username: admin' OR '1'='1
Password: anything
\`\`\`

## Response Analysis

Server trả về thông báo lỗi:

\`\`\`
Error: You have an error in your SQL syntax
\`\`\`

Điều này xác nhận rằng input không được sanitize đúng cách và có thể bị SQL Injection.

# Exploitation

## Step 1: Identify the Query Structure

Ta thử payload sau để xác định cấu trúc câu query:

\`\`\`sql
admin' OR '1'='1' --
\`\`\`

## Step 2: Bypass Authentication

Sau khi hiểu được cấu trúc, ta sử dụng payload:

\`\`\`sql
admin' OR 1=1 LIMIT 1 --
\`\`\`

Câu query cuối cùng sẽ trông như thế này:

\`\`\`sql
SELECT * FROM users WHERE username='admin' OR 1=1 LIMIT 1 -- ' AND password='anything'
\`\`\`

## Step 3: Get the Flag

Khi đăng nhập thành công, ta được chuyển đến dashboard và thấy flag:

\`\`\`
FLAG{SQL_1nj3ct10n_1s_d4ng3r0us}
\`\`\`

# Conclusion

## Lessons Learned

1. **Input Validation**: Luôn validate và sanitize user input
2. **Prepared Statements**: Sử dụng prepared statements để ngăn chặn SQL Injection
3. **Least Privilege**: Database user không nên có quyền quá cao

## Mitigation

Code an toàn nên sử dụng prepared statements:

\`\`\`python
cursor.execute("SELECT * FROM users WHERE username=? AND password=?", (username, password))
\`\`\`

## Tools Used

- Burp Suite
- SQLmap
- Browser Developer Tools

# References

- [OWASP SQL Injection](https://owasp.org/www-community/attacks/SQL_Injection)
- [PortSwigger SQL Injection](https://portswigger.net/web-security/sql-injection)
    `,
  };

  const tableOfContents = [
    { id: 'overview', title: 'Overview' },
    { id: 'reconnaissance', title: 'Reconnaissance' },
    { id: 'exploitation', title: 'Exploitation' },
    { id: 'conclusion', title: 'Conclusion' },
  ];

  useEffect(() => {
    // Auto-detect active section based on scroll
    const handleScroll = () => {
      const sections = tableOfContents.map((item) => item.id);
      let current = '';

      for (const section of sections) {
        const element = document.getElementById(section);
        if (element) {
          const rect = element.getBoundingClientRect();
          if (rect.top <= 150) {
            current = section;
          }
        }
      }

      setActiveSection(current);
    };

    window.addEventListener('scroll', handleScroll);
    handleScroll();

    return () => window.removeEventListener('scroll', handleScroll);
  }, []);

  const scrollToSection = (id: string) => {
    const element = document.getElementById(id);
    if (element) {
      const offset = 100;
      const elementPosition = element.getBoundingClientRect().top;
      const offsetPosition = elementPosition + window.pageYOffset - offset;

      window.scrollTo({
        top: offsetPosition,
        behavior: 'smooth',
      });
    }
  };

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
        {/* Back button */}
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

        <div className="grid grid-cols-1 lg:grid-cols-4 gap-6 lg:gap-8">
          {/* Left: Table of Contents (Desktop) */}
          <aside className="hidden lg:block lg:col-span-1">
            <motion.div
              className="bg-white dark:bg-gray-800 rounded-2xl p-6 shadow-xl sticky top-24"
              initial={{ opacity: 0, x: -20 }}
              animate={{ opacity: 1, x: 0 }}
              transition={{ duration: 0.6 }}
            >
              <h3 className="text-lg font-bold text-gray-900 dark:text-white mb-6">
                Contents
              </h3>
              <nav className="space-y-2">
                {tableOfContents.map((item) => (
                  <button
                    key={item.id}
                    onClick={() => scrollToSection(item.id)}
                    className={`w-full text-left px-3 py-2 rounded-lg transition-all duration-200 text-sm ${
                      activeSection === item.id
                        ? 'bg-cyan-500 text-white'
                        : 'text-gray-600 dark:text-gray-300 hover:bg-gray-100 dark:hover:bg-gray-700'
                    }`}
                  >
                    <div className="flex items-center justify-between">
                      <span>{item.title}</span>
                      {activeSection === item.id && (
                        <ChevronRight className="w-4 h-4" />
                      )}
                    </div>
                  </button>
                ))}
              </nav>
            </motion.div>
          </aside>

          {/* Right: Content */}
          <main className="lg:col-span-3">
            <motion.article
              className="bg-white dark:bg-gray-800 rounded-2xl p-6 sm:p-8 shadow-xl"
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.6 }}
            >
              {/* Header */}
              <header className="mb-8 pb-8 border-b border-gray-200 dark:border-gray-700">
                <h1 className="text-3xl sm:text-4xl font-bold text-gray-900 dark:text-white mb-4">
                  {writeup.title}
                </h1>

                {/* Meta info */}
                <div className="flex flex-wrap items-center gap-3 sm:gap-4 text-sm text-gray-600 dark:text-gray-400 mb-4">
                  <div className="flex items-center gap-2">
                    <Calendar className="w-4 h-4" />
                    <span>{writeup.date}</span>
                  </div>
                  <div className="flex items-center gap-2">
                    <Clock className="w-4 h-4" />
                    <span>{writeup.readTime} read</span>
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
                <div className="flex flex-wrap items-center gap-2">
                  <Tag className="w-4 h-4 text-gray-400" />
                  {writeup.tags.map((tag, i) => (
                    <span
                      key={i}
                      className="px-3 py-1 bg-gray-100 dark:bg-gray-700 text-gray-700 dark:text-gray-300 rounded-full text-xs"
                    >
                      {tag}
                    </span>
                  ))}
                </div>
              </header>

              {/* Content */}
              <div className="prose prose-lg dark:prose-invert max-w-none">
                {writeup.content.split('\n').map((line, i) => {
                  // Parse markdown-style content
                  if (line.startsWith('# ')) {
                    const id = line
                      .substring(2)
                      .toLowerCase()
                      .replace(/ /g, '-');
                    return (
                      <h1
                        key={i}
                        id={id}
                        className="text-3xl font-bold text-gray-900 dark:text-white mt-8 mb-4"
                      >
                        {line.substring(2)}
                      </h1>
                    );
                  } else if (line.startsWith('## ')) {
                    const id = line
                      .substring(3)
                      .toLowerCase()
                      .replace(/ /g, '-');
                    return (
                      <h2
                        key={i}
                        id={id}
                        className="text-2xl font-bold text-gray-900 dark:text-white mt-6 mb-3"
                      >
                        {line.substring(3)}
                      </h2>
                    );
                  } else if (line.startsWith('```')) {
                    return null; // Skip code block markers for now
                  } else if (line.trim() === '') {
                    return <br key={i} />;
                  } else {
                    return (
                      <p
                        key={i}
                        className="text-gray-700 dark:text-gray-300 leading-relaxed mb-4"
                      >
                        {line}
                      </p>
                    );
                  }
                })}
              </div>

              {/* Mobile TOC at bottom */}
              <div className="lg:hidden mt-12 pt-8 border-t border-gray-200 dark:border-gray-700">
                <h3 className="text-lg font-bold text-gray-900 dark:text-white mb-4">
                  Table of Contents
                </h3>
                <div className="grid grid-cols-2 gap-2">
                  {tableOfContents.map((item) => (
                    <button
                      key={item.id}
                      onClick={() => scrollToSection(item.id)}
                      className="text-left px-4 py-2 bg-gray-100 dark:bg-gray-700 text-gray-700 dark:text-gray-300 rounded-lg hover:bg-cyan-500 hover:text-white transition-colors text-sm"
                    >
                      {item.title}
                    </button>
                  ))}
                </div>
              </div>
            </motion.article>
          </main>
        </div>
      </div>
    </div>
  );
}
