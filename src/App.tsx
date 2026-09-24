import { AppLayout } from './components/AppLayout'
import { mockHosts } from './data/mockHosts'
import { SettingsProvider } from './lib/settings'

export default function App() {
  // No seeded sessions: real ones are restored from sessions.json on launch.
  return (
    <SettingsProvider>
      <AppLayout hosts={mockHosts} />
    </SettingsProvider>
  )
}
