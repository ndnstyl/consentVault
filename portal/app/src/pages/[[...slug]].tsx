import type { GetStaticPaths, GetStaticProps } from 'next';
import { PortalApp } from '../components/PortalApp.tsx';
import { staticPaths } from '../lib/routes.ts';

export const getStaticPaths: GetStaticPaths = async () => ({
  paths: staticPaths().map((p) => ({ params: { slug: p === '/' ? [] : p.split('/').filter(Boolean) } })),
  fallback: false,
});
export const getStaticProps: GetStaticProps = async ({ params }) => ({ props: { path: '/' + ((params?.slug as string[] | undefined) ?? []).join('/') } });

export default function Page({ path }: { path: string }) {
  return <PortalApp initial={path} />;
}
