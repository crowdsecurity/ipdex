import React from 'react';
import { motion } from 'framer-motion';

interface TerminalProps {
    children: React.ReactNode;
    title?: string;
    className?: string;
}

export const Terminal: React.FC<TerminalProps> = ({ children, title = "bash", className = "" }) => {
    return (
        <motion.div
            className={`rounded-lg overflow-hidden shadow-2xl bg-[#1e1e1e] border border-gray-800 ${className}`}
            initial={{ opacity: 0, y: 20 }}
            whileInView={{ opacity: 1, y: 0 }}
            viewport={{ once: true }}
            transition={{ duration: 0.5 }}
        >
            <div className="bg-[#2d2d2d] px-4 py-2 flex items-center gap-2 border-b border-gray-800">
                <div className="flex gap-2">
                    <div className="w-3 h-3 rounded-full bg-[#ff5f56]" />
                    <div className="w-3 h-3 rounded-full bg-[#ffbd2e]" />
                    <div className="w-3 h-3 rounded-full bg-[#27c93f]" />
                </div>
                <div className="flex-1 text-center text-xs text-gray-400 font-mono">
                    {title}
                </div>
            </div>
            <div className="p-4 font-mono text-sm text-gray-300 overflow-x-auto">
                {children}
            </div>
        </motion.div>
    );
};
