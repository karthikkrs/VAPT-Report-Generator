import { ReactNode } from 'react';
import { motion } from 'framer-motion';
import { Shield, ExternalLink } from 'lucide-react';

interface LayoutProps {
  children: ReactNode;
}

export function Layout({ children }: LayoutProps) {
  const containerVariants = {
    hidden: { opacity: 0 },
    visible: { 
      opacity: 1,
      transition: { 
        staggerChildren: 0.1,
        delayChildren: 0.2
      }
    }
  };

  return (
    <div className="min-h-screen bg-zinc-50 text-zinc-900 flex flex-col dark:bg-zinc-950 dark:text-zinc-50">
      <main className="container py-8 max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 flex-grow">
        <motion.div
          variants={containerVariants}
          initial="hidden"
          animate="visible"
          className="w-full"
        >
          {children}
        </motion.div>
      </main>
      
      <footer className="border-t py-6 bg-white dark:bg-zinc-900 mt-auto">
        <div className="container flex flex-col items-center justify-between gap-4 md:h-16 md:flex-row max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <motion.div 
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.2 }}
            className="flex items-center space-x-2"
          >
            <Shield className="h-4 w-4 text-blue-600 dark:text-blue-400" />
            <p className="text-sm text-zinc-500 dark:text-zinc-400">
              &copy; {new Date().getFullYear()} vCyberiz SCS. All rights reserved.
            </p>
          </motion.div>
          <motion.div 
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.3 }}
            className="flex items-center space-x-4"
          >
            <a href="#" className="text-sm text-zinc-500 hover:text-zinc-900 dark:text-zinc-400 dark:hover:text-zinc-50 transition-colors flex items-center">
              <ExternalLink className="h-3 w-3 mr-1" />
              Privacy
            </a>
            <span className="text-zinc-300 dark:text-zinc-700">•</span>
            <a href="#" className="text-sm text-zinc-500 hover:text-zinc-900 dark:text-zinc-400 dark:hover:text-zinc-50 transition-colors flex items-center">
              <ExternalLink className="h-3 w-3 mr-1" />
              Terms
            </a>
            <span className="text-zinc-300 dark:text-zinc-700">•</span>
            <a href="#" className="text-sm text-zinc-500 hover:text-zinc-900 dark:text-zinc-400 dark:hover:text-zinc-50 transition-colors flex items-center">
              <ExternalLink className="h-3 w-3 mr-1" />
              Contact
            </a>
          </motion.div>
        </div>
      </footer>
    </div>
  );
}