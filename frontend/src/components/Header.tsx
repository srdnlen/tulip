import { format, parse } from "date-fns";
import { Suspense, useState } from "react";
import { useHotkeys } from 'react-hotkeys-hook';
import {
  Link,
  useParams,
  useSearchParams,
  useNavigate,
} from "react-router-dom";
import ReactDiffViewer from "react-diff-viewer";

import {
  END_FILTER_KEY,
  SERVICE_FILTER_KEY,
  START_FILTER_KEY,
  TEXT_FILTER_KEY,
  FIRST_DIFF_KEY,
  SECOND_DIFF_KEY,
  SERVICE_REFETCH_INTERVAL_MS,
  REPR_ID_KEY,
} from "../const";
import {
  useGetFlowQuery,
  useGetServicesQuery,
} from "../api";
import { getTickStuff } from "../tick";
import {usePrefersDarkMode} from "../hooks/usePrefersDarkMode";
import { SunIcon, MoonIcon } from "@heroicons/react/solid";

function ServiceSelection() {
  const FILTER_KEY = SERVICE_FILTER_KEY;

  // TODO add all, maybe user react-select

  const { data: services } = useGetServicesQuery(undefined, {
    pollingInterval: SERVICE_REFETCH_INTERVAL_MS,
  });

  const service_select = [
    {
      ip: "",
      port: 0,
      name: "all",
    },
    ...(services || []),
  ];
  let [searchParams, setSearchParams] = useSearchParams();
  return (
    <select
      className={"w-48"}
      value={searchParams.get(FILTER_KEY) ?? ""}
      onChange={(event) => {
        let serviceFilter = event.target.value;
        if (serviceFilter && serviceFilter != "all") {
          searchParams.set(FILTER_KEY, serviceFilter);
        } else {
          searchParams.delete(FILTER_KEY);
        }
        setSearchParams(searchParams);
      }}
    >
      {service_select.map((service) => (
        <option key={service.name} value={service.name}>
          {service.name}
        </option>
      ))}
    </select>
  );
}

function DarkModeSwitch() {
  const [prefersDarkMode, setPrefersDarkMode] = usePrefersDarkMode();

  return (
    <button
      onClick={() => setPrefersDarkMode(prev => !prev)}
        className={`w-9 flex justify-center px-0 bg-gray-200 py-1 rounded-md border border-transparent placeholder:text-gray-500 focus:outline-none focus:ring-2 focus:ring-blue-500 whitespace-nowrap ${
          prefersDarkMode ? "bg-amber-300/20 text-zinc-100 border-zinc-600" : "bg-gray-200 text-gray-900"
        }`}
      aria-label="Toggle dark mode"
    >
      {prefersDarkMode ? (
        <SunIcon className="w-6 h-6 text-yellow-400" />
      ) : (
        <MoonIcon className="w-6 h-6 text-gray-800" />
      )}
    </button>
  );
}

function TextSearch() {
  const FILTER_KEY = TEXT_FILTER_KEY;
  let [searchParams, setSearchParams] = useSearchParams();
  useHotkeys('s', (e) => {
    let el = document.getElementById('search') as HTMLInputElement;
    el?.focus();
    el?.select();
    e.preventDefault()
  });
  return (
    <div>
      <input
        type="text"
        placeholder="regex"
        id="search"
        value={searchParams.get(FILTER_KEY) || ""}
        onChange={(event) => {
          let textFilter = event.target.value;
          if (textFilter) {
            searchParams.set(FILTER_KEY, textFilter);
          } else {
            searchParams.delete(FILTER_KEY);
          }
          setSearchParams(searchParams);
        }}
      ></input>
    </div>
  );
}


function StartDateSelection() {
  let { startTickParam, setTimeParam } = getTickStuff();
  return (
    <div>
      <input
        className="w-20"
        id="startdateselection"
        type="number"
        placeholder="from"
        value={startTickParam}
        onChange={(event) => {
          setTimeParam(event.target.value == "" ? null : parseInt(event.target.value), START_FILTER_KEY);
        }}
      ></input>
    </div>
  );
}

function EndDateSelection() {
  let { endTickParam, setTimeParam } = getTickStuff();
  return (
    <div>
      <input
        className="w-20"
        id="enddateselection"
        type="number"
        placeholder="to"
        value={endTickParam}
        onChange={(event) => {
          setTimeParam(event.target.value == "" ? null : parseInt(event.target.value), END_FILTER_KEY);
        }}
      ></input>
    </div>
  );
}

function FirstDiff() {
  let params = useParams();
  let [searchParams, setSearchParams] = useSearchParams();
  const [firstFlow, setFirstFlow] = useState<string>(
    searchParams.get(FIRST_DIFF_KEY) ?? ""
  );

  function setFirstDiffFlow() {
    let textFilter = params.id;
    let reprId = searchParams.get(REPR_ID_KEY);
    let reprIdSlug = reprId ? `${textFilter}:${reprId}` : `${textFilter}`
    if (textFilter) {
      searchParams.set(FIRST_DIFF_KEY, reprIdSlug);
      setFirstFlow(reprIdSlug);
    } else {
      searchParams.delete(FIRST_DIFF_KEY);
      setFirstFlow("");
    }
    setSearchParams(searchParams);
  }

  useHotkeys("f", () => {
    setFirstDiffFlow();
  });

  return (
    <input
      type="text"
      className="w-56 box-border"
      placeholder="First Diff ID"
      readOnly
      value={firstFlow}
      onClick={(event) => setFirstDiffFlow()}
      onContextMenu={(event) => {
        searchParams.delete(FIRST_DIFF_KEY);
        setFirstFlow("");
        setSearchParams(searchParams);
        event.preventDefault();
      }}
    ></input>
  );
}

function SecondDiff() {
  let params = useParams();
  let [searchParams, setSearchParams] = useSearchParams();
  const [secondFlow, setSecondFlow] = useState<string>(
    searchParams.get(SECOND_DIFF_KEY) ?? ""
  );

  function setSecondDiffFlow() {
    let textFilter = params.id;
    let reprId = searchParams.get(REPR_ID_KEY);
    let reprIdSlug = reprId ? `${textFilter}:${reprId}` : `${textFilter}`
    if (textFilter) {
      searchParams.set(SECOND_DIFF_KEY, reprIdSlug);
      setSecondFlow(reprIdSlug);
    } else {
      searchParams.delete(SECOND_DIFF_KEY);
      setSecondFlow("");
    }
    setSearchParams(searchParams);
  }

  useHotkeys("e", () => {
    setSecondDiffFlow();
  });

  return (
    <input
      type="text"
      className="w-56 box-border"
      placeholder="Second Diff ID"
      readOnly
      value={secondFlow}
      onClick={(event) => setSecondDiffFlow()}
      onContextMenu={(event) => {
        searchParams.delete(SECOND_DIFF_KEY);
        setSecondFlow("");
        setSearchParams(searchParams);
        event.preventDefault();
      }}
    ></input>
  );
}

function Diff() {
  let params = useParams();

  let [searchParams] = useSearchParams();

  let navigate = useNavigate();

  function navigateToDiff() {
    navigate(`/diff/${params.id ?? ""}?${searchParams}`, { replace: true });
  }

  useHotkeys("d", () => {
    navigateToDiff();
  });

  return (
    <button
      className="whitespace-nowrap bg-amber-100 text-gray-800 rounded-md px-2 py-1 dark:bg-amber-500/20 dark:text-amber-100 dark:ring-1 dark:ring-amber-300/20"
      onClick={() => {
        navigateToDiff()
      }}
    >
      Diff
    </button>
  );
}

export function Header() {
  let { currentTick, setToLastnTicks, setTimeParam } = getTickStuff();
  let [searchParams] = useSearchParams();

  let navigate = useNavigate();
 
  useHotkeys('g', () => navigate(`/corrie?${searchParams}`, { replace: true }));
  useHotkeys('a', () => setToLastnTicks(5));
  useHotkeys('c', () => {
    (document.getElementById("startdateselection") as HTMLInputElement).value = "";
    (document.getElementById("enddateselection") as HTMLInputElement).value = "";
    setTimeParam(null, START_FILTER_KEY);
    setTimeParam(null, END_FILTER_KEY);
  });

  return (
    <>
      <Link to={`/?${searchParams}`}>
        <div className="header-icon">🌷</div>
      </Link>
      <div>
        <TextSearch></TextSearch>
      </div>
      <div>
        <Suspense>
          <ServiceSelection></ServiceSelection>
        </Suspense>
      </div>
      <div>
        <StartDateSelection></StartDateSelection>
      </div>
      <div>
        <EndDateSelection></EndDateSelection>
      </div>
      <button
        className="whitespace-nowrap bg-amber-100 text-gray-800 rounded-md px-2 py-1 dark:bg-amber-500/20 dark:text-amber-100 dark:ring-1 dark:ring-amber-300/20"
        onClick={() => setToLastnTicks(5)}
      >
        Last 5 ticks
      </button>
      <Link to={`/corrie?${searchParams}`}>
        <div className="whitespace-nowrap bg-blue-100 text-gray-800 rounded-md px-2 py-1 dark:bg-blue-500/20 dark:text-blue-100 dark:ring-1 dark:ring-blue-300/10">
          Graph view
        </div>
      </Link>
      <FirstDiff />
      <SecondDiff />
      <Suspense>
        <Diff />
      </Suspense>
      <div
        className="ml-auto"
        style={{
          display: "flex",
          justifyContent: "center",
          alignContent: "center",
          flexDirection: "column",
        }}
      >
        Current: {currentTick}
      </div>
      <div className="mr-4">
          <DarkModeSwitch />
      </div>
    </>
  );
}
