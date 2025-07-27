import { Link } from 'react-router-dom'
import './LandingPage.css'

function LandingPage() {
  return (
    <div className="landing-container">
      
        {/* O nosso novo botão. É um link, mas vamos estilizá-lo como um botão. */}
        <Link to="/dashboard" className="explore-button">
          Explore Application
        </Link>
    </div>
  )
}

export default LandingPage