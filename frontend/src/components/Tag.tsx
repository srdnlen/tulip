import classNames from "classnames";
import Color from "color";

const computeColorFromString = (str: string) => {
  const hue = Array.from(str).reduce(
    (hash, char) => 0 | (31 * hash + char.charCodeAt(0)),
    0
  );
  return Color(`hsl(${hue}, 100%, 50%)`).hex();
};

// Hardcode colors here
const tagBackgroundColorMap: Record<string, string> = {
  "http": "rgb(255, 39, 244)",
  "tcp": "rgb(31, 109, 255)",
  fishy: "rgb(191, 219, 254)",
  blocked: "rgb(233, 213, 255)",
  "flag-out": "rgb(255, 73, 63)",
  "flag-in": "rgb(0, 190, 21)",
  "flag-id": "rgb(0, 231, 247)",
};

const tagForegroundColorMap: Record<string, string> = {
  "http": "#fff",
  "tcp": "#fff",
  "flag-out": "#fff",
  "flag-in": "#fff",
  "flag-id": "#000"
};

export function tagToColor(tag: string) {
  return tagBackgroundColorMap[tag] ?? computeColorFromString(tag);
}
interface TagProps {
  tag: string;
  color?: string;
  disabled?: boolean;
  excluded?: boolean;
  onClick?: () => void;
}
export const Tag = ({ tag, color, disabled = false, excluded = false, onClick }: TagProps) => {
  let tagBackgroundColor, tagTextColor;
  var text = tag.replace("flagstore-", "");

  var isFlagstoreTag = tag.startsWith("flagstore-")
  let styleAsFlagstoreTag = isFlagstoreTag && !disabled && !excluded

  // if tag is flagstore-related, leave styling to the classes below
  if (styleAsFlagstoreTag) {
    tagBackgroundColor = ""
    tagTextColor = ""
  }  else {
    tagBackgroundColor = disabled ? "" : color ?? tagToColor(tag);
    tagTextColor = disabled
      ? ""
      : tagForegroundColorMap[tag]
        ?? (Color(tagBackgroundColor).isDark()
          ? "#fff"
          : "#000")
  }

  return (
    <div
      onClick={onClick}
      className={classNames("border-[1.5px] p-2.5 cursor-pointer rounded-md uppercase text-xs h-5 text-center flex items-center hover:opacity-90 transition-colors duration-250 text-ellipsis overflow-hidden whitespace-nowrap", {
        "border-transparent": disabled || excluded,
        "bg-gray-300": disabled,
        "dark:bg-gray-700": disabled,

        "bg-neutral-900": excluded,
        "text-white": excluded,
        "dark:bg-red-900/50": excluded,


        "border-gray-400": styleAsFlagstoreTag,
        "text-gray-800 dark:text-gray-300": styleAsFlagstoreTag,
        "bg-transparent": styleAsFlagstoreTag,
      })}
      style={{
        backgroundColor: tagBackgroundColor,
        borderColor: tagBackgroundColor,
        color: tagTextColor,
      }}
    >
      <span  style={excluded ? { textDecoration: 'line-through' } : {}}>{text}</span>
    </div>
  );
};
