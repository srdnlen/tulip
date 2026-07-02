import classNames from "classnames";

export interface RadioGroupProps {
  options: string[];
  value: string;
  className: string;
  onChange: (option: string) => void;
}

export function RadioGroup(props: RadioGroupProps) {
  return (
    <div className={props.className}>
      {props.options.map((option) => (
        <div
          key={option}
          onClick={() => props.onChange(option)}
          className={classNames("py-1 px-2 rounded-md cursor-pointer hover:bg-gray-100 dark:hover:bg-zinc-700", {
            "bg-gray-200 dark:bg-zinc-700 dark:text-zinc-100": option === props.value,
          })}
        >
          {option}
        </div>
      ))}
    </div>
  );
}
