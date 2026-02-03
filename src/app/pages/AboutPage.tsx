import { motion } from 'motion/react';

import { User, Award, Calendar, MapPin } from 'lucide-react';

import { useRef } from 'react';

import { useScrollAnimation } from '@/app/hooks/useScrollAnimation';



export function AboutPage() {
  

  const avatarRef = useRef<HTMLDivElement>(null);

  const descriptionRef = useRef<HTMLDivElement>(null);

  const timelineRef = useRef<HTMLDivElement>(null);

  

  const isAvatarVisible = useScrollAnimation(avatarRef);

  const isDescriptionVisible = useScrollAnimation(descriptionRef);

  const isTimelineVisible = useScrollAnimation(timelineRef);



  const achievements = [

    {

      year: '1/2026',

      title: 'WINTER-MTA-CTF',

      description: 'Ranked 1st place in the WINTER MTA CTF competition.',

    },

    {

      year: '11/2025',

      title: 'Final Round - Cyber Security Contest Viet Nam ',

      description: 'Awarded a consolation prize (Top 12/56), CSCV2025',

    },

    {

      year: '10/2025',

      title: 'Preliminary Round - Cyber Security Contest Viet Nam ',

      description: 'Ranked 34th out of 345 contestants in the preliminary round of CSCV2025',

    },

    {

      year: '9/2025',

      title: 'Cyber Security - Military Technical ',

      description: 'Began studying digital Cyber Security at the Military Technical Academy (MTA).',

    },

  ];



  return (

    <div className="min-h-screen bg-[#f4f4f4] dark:bg-gray-900 pt-20">

      <div className="max-w-7xl mx-auto px-6 py-12">

        <motion.div

          className="grid grid-cols-1 lg:grid-cols-3 gap-12"

          initial={{ opacity: 0, y: 20 }}

          animate={{ opacity: 1, y: 0 }}

          transition={{ duration: 0.6 }}

        >

          {/* Left: Avatar & Info */}

          <div className="lg:col-span-1">

            <motion.div

              className="bg-white dark:bg-gray-800 rounded-2xl p-8 shadow-xl sticky top-24"

              whileHover={{ scale: 1.02 }}

              transition={{ duration: 0.3 }}

            >

              {/* Avatar */}
<div className="relative w-48 h-48 mx-auto mb-6">
  <div className="w-full h-full rounded-full bg-gradient-to-br from-cyan-500 to-blue-500 flex items-center justify-center overflow-hidden border-4 border-white dark:border-gray-800 shadow-lg">
    
    {/* DÁN ĐOẠN NÀY VÀO ĐÂY (Thay cho cái icon <User ... /> cũ) */}
    <img 
      src="https://lh3.googleusercontent.com/u/0/d/1B_gi78gHVS7rS_oMOa2FbGnKwRgoKALP" 
      alt="Manh Khang Avatar"
      className="w-full h-full object-cover"
      onError={(e) => {
        e.currentTarget.src = "https://ui-avatars.com/api/?name=Manh+Khang&background=06b6d4&color=fff";
      }}
    />
    {/* -------------------------------------------------------- */}

  </div>
  <div className="absolute -bottom-2 -right-2 bg-green-500 w-12 h-12 rounded-full border-4 border-white dark:border-gray-800 flex items-center justify-center">
    <Award className="w-6 h-6 text-white" />
  </div>
</div>



              {/* Name */}

              <h1 className="text-2xl font-bold text-gray-900 dark:text-white text-center mb-2">

                Le Manh Khang

              </h1>

              <p className="text-cyan-500 text-center mb-6">Cybersecurity Researcher</p>



              {/* Info */}

              <div className="space-y-4">

                <div className="flex items-center gap-3 text-gray-600 dark:text-gray-300">

                  <MapPin className="w-5 h-5 text-cyan-500" />

                  <span>Military Technical Academy</span>

                </div>

                <div className="flex items-center gap-3 text-gray-600 dark:text-gray-300">

                  <Calendar className="w-5 h-5 text-cyan-500" />

                  <span>Student since 2025</span>

                </div>

              </div>



              {/* Stats */}

              <div className="grid grid-cols-2 gap-4 mt-6 pt-6 border-t border-gray-200 dark:border-gray-700">

                <div className="text-center">

                  <div className="text-2xl font-bold text-gray-900 dark:text-white">122</div>

                  <div className="text-sm text-gray-600 dark:text-gray-400">Writeups</div>

                </div>

                <div className="text-center">

                  <div className="text-2xl font-bold text-gray-900 dark:text-white">35</div>

                  <div className="text-sm text-gray-600 dark:text-gray-400">CTFs</div>

                </div>

              </div>

            </motion.div>

          </div>



          {/* Right: Description & Timeline */}

          <div className="lg:col-span-2 space-y-8">

            {/* Description */}

            <motion.div

              className="bg-white dark:bg-gray-800 rounded-2xl p-8 shadow-xl"

              initial={{ opacity: 0, x: 20 }}

              animate={{ opacity: 1, x: 0 }}

              transition={{ delay: 0.2, duration: 0.6 }}

            >

              <h2 className="text-3xl font-bold text-gray-900 dark:text-white mb-6">About Me</h2>

              <div className="space-y-4 text-gray-600 dark:text-gray-300 leading-relaxed">

                <p>

                  



Hi! My name is Le Manh Khang, and I am currently studying at the Military Technical Academy. I am passionate about Cyber Security and am always seeking new challenges in protecting systems and data..

                </p>

                <p>

                  This blog was created to share knowledge, experience, and writeups from the CTF competitions I have participated in. I hope my articles will be useful to the Cyber Security community.

                </p>

                <p>

                  My areas of interest include: Forensics, Reverse Engineering, Osint, and Crypto.

                </p>

              </div>

            </motion.div>



            {/* Timeline */}

            <motion.div

              className="bg-white dark:bg-gray-800 rounded-2xl p-8 shadow-xl"

              initial={{ opacity: 0, x: 20 }}

              animate={{ opacity: 1, x: 0 }}

              transition={{ delay: 0.4, duration: 0.6 }}

            >

              <h2 className="text-3xl font-bold text-gray-900 dark:text-white mb-8">

                Achievements & Timeline

              </h2>



              <div className="relative">

                {/* Vertical line */}

                <div className="absolute left-4 top-0 bottom-0 w-0.5 bg-gradient-to-b from-cyan-500 to-blue-500" />



                {/* Timeline items */}

                <div className="space-y-8">

                  {achievements.map((achievement, index) => (

                    <motion.div

                      key={index}

                      className="relative pl-12"

                      initial={{ opacity: 0, x: -20 }}

                      whileInView={{ opacity: 1, x: 0 }}

                      viewport={{ once: true }}

                      transition={{ delay: index * 0.1, duration: 0.5 }}

                    >

                      {/* Dot */}

                      <div className="absolute left-0 w-8 h-8 bg-cyan-500 rounded-full border-4 border-white dark:border-gray-800 flex items-center justify-center">

                        <Award className="w-4 h-4 text-white" />

                      </div>



                      {/* Content */}

                      <div className="bg-gray-50 dark:bg-gray-700/50 rounded-xl p-6 hover:shadow-lg transition-shadow">

                        <div className="flex items-center gap-3 mb-2">

                          <span className="px-3 py-1 bg-cyan-500 text-white text-sm font-semibold rounded-full">

                            {achievement.year}

                          </span>

                        </div>

                        <h3 className="text-xl font-bold text-gray-900 dark:text-white mb-2">

                          {achievement.title}

                        </h3>

                        <p className="text-gray-600 dark:text-gray-300">

                          {achievement.description}

                        </p>

                      </div>

                    </motion.div>

                  ))}

                </div>

              </div>

            </motion.div>

          </div>

        </motion.div>

      </div>

    </div>

  );

}