import type { AppProps } from 'next/app';
import { Montserrat, Cormorant_Garamond } from 'next/font/google';
import localFont from 'next/font/local';
import '../styles/tokens.css';
import '../styles/portal.css';

// Fonts are self-hosted at build time: no visitor request ever goes to a font CDN.
const montserrat = Montserrat({ subsets: ['latin'], weight: ['500', '600', '700'], variable: '--font-montserrat', display: 'swap' });
const cormorant = Cormorant_Garamond({ subsets: ['latin'], weight: ['600'], variable: '--font-cormorant', display: 'swap' });
const geist = localFont({ src: '../fonts/Geist-Variable.woff2', variable: '--font-geist', display: 'swap', weight: '100 900' });

export default function App({ Component, pageProps }: AppProps) {
  return (
    <div className={`fontroot ${montserrat.variable} ${cormorant.variable} ${geist.variable}`}>
      <Component {...pageProps} />
    </div>
  );
}
