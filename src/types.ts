export type Status = "fail" | "warn" | "pass" | "info" | "skip";

export type Distribution = "public" | "custom";

export interface Location {
  file: string;
  line?: number;
}

export interface Finding {
  id: string;
  title: string;
  status: Status;
  message: string;
  fix?: string;
  docs?: string;
  deadlineId?: string;
  locations?: Location[];
  details?: string[];
  manual?: boolean;
}

export interface Deadline {
  id: string;
  date: string;
  scope: Distribution[];
  feature: string;
  consequence: string;
  source: string;
}

export interface Report {
  tool: string;
  version: string;
  generatedAt: string;
  today: string;
  distribution: Distribution;
  appDir?: string;
  target?: string;
  findings: Finding[];
  deadlines: Deadline[];
}
