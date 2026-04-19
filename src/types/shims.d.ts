declare module "semver" {
  const semver: {
    valid(version: string): string | null;
    compare(left: string, right: string): number;
  };
  export default semver;
}

declare module "@babel/traverse" {
  const traverse: any;
  export type NodePath<T = any> = any;
  export default traverse;
}

declare module "@babel/generator" {
  const generate: any;
  export default generate;
}
