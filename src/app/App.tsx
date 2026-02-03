import {
  BrowserRouter as Router,
  Routes,
  Route,
  Link,
  useLocation,
  useNavigate,
} from "react-router-dom";
import { motion } from "motion/react";
import { Terminal } from "lucide-react";
import { ParticleBackground } from "@/app/components/ParticleBackground";
import { ThemeToggle } from "@/app/components/ThemeToggle";
import { HomePage } from "@/app/pages/HomePage";
import { CategoryPage } from "@/app/pages/CategoryPage";
import { AboutPage } from "@/app/pages/AboutPage";
import { WriteupPage } from "@/app/pages/WriteupPage";
import { useEffect } from "react";

function AppContent() {
  const location = useLocation();
  const navigate = useNavigate();

  // Scroll to top on route change
  useEffect(() => {
    window.scrollTo({ top: 0, behavior: "smooth" });
  }, [location.pathname]);

  // Initialize theme from localStorage
  useEffect(() => {
    const savedTheme = localStorage.getItem("theme");

    if (savedTheme === "light") {
      document.documentElement.classList.remove("dark");
    } else {
      // Default to dark mode
      document.documentElement.classList.add("dark");
      if (!savedTheme) {
        localStorage.setItem("theme", "dark");
      }
    }
  }, []);

  const scrollToCategories = () => {
    if (location.pathname === "/") {
      const categoriesSection = document.getElementById(
        "categories-section",
      );
      if (categoriesSection) {
        categoriesSection.scrollIntoView({
          behavior: "smooth",
          block: "start",
        });
      }
    } else {
      navigate("/");
      setTimeout(() => {
        const categoriesSection = document.getElementById(
          "categories-section",
        );
        if (categoriesSection) {
          categoriesSection.scrollIntoView({
            behavior: "smooth",
            block: "start",
          });
        }
      }, 100);
    }
  };

  const goToHome = () => {
    if (location.pathname === "/") {
      window.scrollTo({ top: 0, behavior: "smooth" });
    } else {
      navigate("/");
    }
  };

  return (
    <div className="min-h-screen bg-[#f4f4f4] dark:bg-gray-900 relative transition-colors duration-300">
      {/* Particle Background */}
      <ParticleBackground />

      {/* Content - relative to be above particles */}
      <div className="relative z-10">
        {/* Header */}
        <motion.header
          className="bg-white/80 dark:bg-gray-800/80 backdrop-blur-md border-b border-gray-200 dark:border-gray-700 sticky top-0 z-50 transition-colors duration-300"
          initial={{ y: -100 }}
          animate={{ y: 0 }}
          transition={{ duration: 0.5 }}
        >
          <div className="max-w-7xl mx-auto px-4 sm:px-6 py-4">
            <div className="flex items-center justify-between">
              {/* Logo */}
              <button onClick={goToHome}>
                <motion.div
                  className="flex items-center gap-2 cursor-pointer"
                  whileHover={{ scale: 1.05 }}
                  transition={{
                    type: "spring",
                    stiffness: 300,
                  }}
                >
                  <Terminal className="w-6 h-6 text-cyan-500" />
                  <span className="text-lg sm:text-xl font-semibold text-gray-900 dark:text-white">
                    kagm1e's Blog
                  </span>
                </motion.div>
              </button>

              {/* Navigation */}
              <nav className="hidden md:flex items-center gap-6">
                <motion.button
                  onClick={goToHome}
                  className="text-gray-700 dark:text-gray-300 hover:text-cyan-500 dark:hover:text-cyan-400 transition-colors relative group"
                  whileHover={{ y: -2 }}
                >
                  Home
                  <span className="absolute bottom-0 left-0 w-0 h-0.5 bg-cyan-500 group-hover:w-full transition-all duration-300" />
                </motion.button>

                <motion.button
                  onClick={scrollToCategories}
                  className="text-gray-700 dark:text-gray-300 hover:text-cyan-500 dark:hover:text-cyan-400 transition-colors relative group"
                  whileHover={{ y: -2 }}
                >
                  Categories
                  <span className="absolute bottom-0 left-0 w-0 h-0.5 bg-cyan-500 group-hover:w-full transition-all duration-300" />
                </motion.button>

                <Link to="/about">
                  <motion.span
                    className="text-gray-700 dark:text-gray-300 hover:text-cyan-500 dark:hover:text-cyan-400 transition-colors relative group cursor-pointer"
                    whileHover={{ y: -2 }}
                  >
                    About
                    <span className="absolute bottom-0 left-0 w-0 h-0.5 bg-cyan-500 group-hover:w-full transition-all duration-300" />
                  </motion.span>
                </Link>

                <ThemeToggle />
              </nav>

              {/* Mobile theme toggle */}
              <div className="md:hidden">
                <ThemeToggle />
              </div>
            </div>

            {/* Mobile Navigation */}
            <nav className="md:hidden flex items-center justify-center gap-4 mt-4 pb-2">
              <button
                onClick={goToHome}
                className="text-sm text-gray-700 dark:text-gray-300 hover:text-cyan-500 dark:hover:text-cyan-400 transition-colors"
              >
                Home
              </button>
              <button
                onClick={scrollToCategories}
                className="text-sm text-gray-700 dark:text-gray-300 hover:text-cyan-500 dark:hover:text-cyan-400 transition-colors"
              >
                Categories
              </button>
              <Link to="/about">
                <span className="text-sm text-gray-700 dark:text-gray-300 hover:text-cyan-500 dark:hover:text-cyan-400 transition-colors">
                  About
                </span>
              </Link>
            </nav>
          </div>
        </motion.header>

        {/* Routes */}
        <Routes>
          <Route path="/" element={<HomePage />} />
          <Route
            path="/category/:category"
            element={<CategoryPage />}
          />
          <Route
            path="/category/:category/writeup/:id"
            element={<WriteupPage />}
          />
          <Route path="/about" element={<AboutPage />} />
        </Routes>

        {/* Footer */}
        <footer className="bg-white dark:bg-gray-800 border-t border-gray-200 dark:border-gray-700 mt-20 transition-colors duration-300">
          <div className="max-w-7xl mx-auto px-6 py-12">
            <div className="grid grid-cols-1 md:grid-cols-4 gap-8 mb-8">
              {/* Brand */}
              <div className="col-span-1 md:col-span-2">
                <div className="flex items-center gap-2 mb-4">
                  <Terminal className="w-6 h-6 text-cyan-500" />
                  <span className="text-xl font-semibold text-gray-900 dark:text-white">
                    kagm1e's Blog
                  </span>
                </div>
                <p className="text-gray-600 dark:text-gray-400 mb-4">
                  Share cybersecurity knowledge through detailed
                  and easy-to-understand writeups. Learn from
                  real-world situations and apply the knowledge
                  to practical applications..
                </p>
              </div>

              {/* Quick Links */}
              <div>
                <h3 className="font-semibold text-gray-900 dark:text-white mb-4">
                  Quick Links
                </h3>
                <ul className="space-y-2">
                  <li>
                    <Link
                      to="/"
                      className="text-gray-600 dark:text-gray-400 hover:text-cyan-500 dark:hover:text-cyan-400 transition-colors"
                    >
                      Home
                    </Link>
                  </li>
                  <li>
                    <button
                      onClick={scrollToCategories}
                      className="text-gray-600 dark:text-gray-400 hover:text-cyan-500 dark:hover:text-cyan-400 transition-colors"
                    >
                      Categories
                    </button>
                  </li>
                  <li>
                    <Link
                      to="/about"
                      className="text-gray-600 dark:text-gray-400 hover:text-cyan-500 dark:hover:text-cyan-400 transition-colors"
                    >
                      About
                    </Link>
                  </li>
                </ul>
              </div>

              {/* Resources */}
              <div>
                <h3 className="font-semibold text-gray-900 dark:text-white mb-4"></h3>
                <ul className="space-y-2">
                  <li>
                    <a
                      href="#"
                      className="text-gray-600 dark:text-gray-400 hover:text-cyan-500 dark:hover:text-cyan-400 transition-colors"
                    ></a>
                  </li>
                  <li>
                    <a
                      href="#"
                      className="text-gray-600 dark:text-gray-400 hover:text-cyan-500 dark:hover:text-cyan-400 transition-colors"
                    ></a>
                  </li>
                  <li>
                    <a
                      href="#"
                      className="text-gray-600 dark:text-gray-400 hover:text-cyan-500 dark:hover:text-cyan-400 transition-colors"
                    ></a>
                  </li>
                </ul>
              </div>
            </div>

            {/* Copyright */}
            <div className="border-t border-gray-200 dark:border-gray-700 pt-8 text-center text-gray-600 dark:text-gray-400">
              <p>© 2026 kagm1e's Blog. </p>
              <p className="mt-2 text-sm"></p>
            </div>
          </div>
        </footer>
      </div>
    </div>
  );
}

function App() {
  return (
    <Router>
      <AppContent />
    </Router>
  );
}

export default App;