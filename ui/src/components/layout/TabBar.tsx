import type { TabId } from "../../types";

export interface TabBarProps {
  activeTab: TabId;
  onTabChange: (t: TabId) => void;
  tabs?: { id: TabId; label: string }[]; // default [{dashboard,'Dashboard'},{flows,'Flows'}]
}

export function TabBar(_props: TabBarProps) {
  return <div data-component="TabBar">TabBar</div>;
}

export default TabBar;
