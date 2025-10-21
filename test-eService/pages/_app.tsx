import "@/styles/globals.css";
import type { AppProps } from "next/app";
import Head from "next/head";

export default function App({ Component, pageProps }: AppProps) {
  return (
    <>
      <Head>
        <title>eService</title>
        <link rel="icon" href="/adorsys-logo.png" />
      </Head>
      <Component {...pageProps} />
    </>
  );
}
