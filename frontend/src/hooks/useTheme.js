import { useEffect, useState } from 'react'

const KEY = 'cg-theme'

export default function useTheme() {
  const [theme, setTheme] = useState(() => {
    try { return localStorage.getItem(KEY) === 'dark' ? 'dark' : 'light' } catch { return 'light' }
  })

  useEffect(() => {
    document.documentElement.classList.toggle('dark', theme === 'dark')
    try { localStorage.setItem(KEY, theme) } catch { /* storage unavailable */ }
  }, [theme])

  const toggle = () => setTheme((t) => (t === 'dark' ? 'light' : 'dark'))
  return { theme, toggle }
}