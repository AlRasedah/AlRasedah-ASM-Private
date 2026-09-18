import { useCallback, useMemo } from "react";
import { useSearchParams } from "react-router-dom";

export type FilterValue = string | string[] | undefined;

/** Filters stored in the URL query string so views are shareable and survive reloads. */
export function useFilters<K extends string>(multi: readonly K[] = []) {
  const [params, setParams] = useSearchParams();

  const get = useCallback((k: K): string | undefined => params.get(k) ?? undefined, [params]);
  const getAll = useCallback((k: K): string[] => params.getAll(k), [params]);

  const set = useCallback(
    (k: K, v: FilterValue) => {
      setParams((prev) => {
        const next = new URLSearchParams(prev);
        next.delete(k);
        if (Array.isArray(v)) v.forEach((x) => next.append(k, x));
        else if (v !== undefined && v !== "") next.set(k, v);
        if (k !== ("page" as K)) next.delete("page");
        return next;
      }, { replace: true });
    },
    [setParams],
  );

  const setMany = useCallback(
    (values: Partial<Record<K, FilterValue>>) => {
      setParams((prev) => {
        const next = new URLSearchParams(prev);
        for (const [k, v] of Object.entries(values) as [string, FilterValue][]) {
          next.delete(k);
          if (Array.isArray(v)) v.forEach((x) => next.append(k, x));
          else if (v !== undefined && v !== "") next.set(k, v);
        }
        if (!("page" in values)) next.delete("page");
        return next;
      }, { replace: true });
    },
    [setParams],
  );

  const clear = useCallback(() => setParams(new URLSearchParams(), { replace: true }), [setParams]);

  const query = useMemo(() => {
    const q: Record<string, string | string[]> = {};
    params.forEach((_, key) => {
      q[key] = (multi as readonly string[]).includes(key) ? params.getAll(key) : (params.get(key) as string);
    });
    return q;
  }, [params, multi]);

  const page = Number(params.get("page") ?? 1) || 1;
  return { get, getAll, set, setMany, clear, query, page, setPage: (p: number) => set("page" as K, String(p)) };
}
