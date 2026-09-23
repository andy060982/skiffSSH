import { AppLayout } from './components/AppLayout'
import { mockHosts } from './data/mockHosts'

export default function App() {
  // No seeded sessions: real ones are restored from sessions.json on launch.
  return <AppLayout hosts={mockHosts} />
}
