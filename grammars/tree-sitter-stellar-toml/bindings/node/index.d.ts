export interface Language {
  name: string;
  version: number;
}

declare const stellarToml: {
  name: string;
  parse(content: string): unknown;
  nodeTypeInfo: unknown[];
  language: Language;
};

export = stellarToml;
