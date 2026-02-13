import { useState, useEffect, useCallback, useRef } from 'react';

/**
 * Custom hook for API calls with loading, error, and data states.
 *
 * @param {Function} apiFunc - The API function to call
 * @param {Array} deps - Dependencies that trigger a refetch
 * @param {Object} options - Configuration options
 * @returns {{ data, loading, error, refetch, setData }}
 */
export function useApi(apiFunc, deps = [], options = {}) {
  const {
    immediate = true,
    initialData = null,
    onSuccess = null,
    onError = null,
    transform = null,
  } = options;

  const [data, setData] = useState(initialData);
  const [loading, setLoading] = useState(immediate);
  const [error, setError] = useState(null);
  const mountedRef = useRef(true);
  const abortRef = useRef(null);

  const execute = useCallback(
    async (...args) => {
      try {
        setLoading(true);
        setError(null);

        // Cancel previous request if still in flight
        if (abortRef.current) {
          abortRef.current.abort();
        }
        abortRef.current = new AbortController();

        const response = await apiFunc(...args);

        if (!mountedRef.current) return;

        const result = transform ? transform(response.data) : response.data;
        setData(result);

        if (onSuccess) {
          onSuccess(result);
        }

        return result;
      } catch (err) {
        if (!mountedRef.current) return;

        // Ignore abort errors
        if (err?.name === 'AbortError' || err?.code === 'ERR_CANCELED') return;

        const errorMessage =
          err?.message || err?.data?.detail || 'An unexpected error occurred';
        setError(errorMessage);

        if (onError) {
          onError(err);
        }

        return null;
      } finally {
        if (mountedRef.current) {
          setLoading(false);
        }
      }
    },
    [apiFunc, transform, onSuccess, onError]
  );

  useEffect(() => {
    mountedRef.current = true;
    if (immediate) {
      execute();
    }
    return () => {
      mountedRef.current = false;
      if (abortRef.current) {
        abortRef.current.abort();
      }
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, deps);

  return {
    data,
    loading,
    error,
    refetch: execute,
    setData,
  };
}

/**
 * Hook for paginated API calls.
 */
export function usePaginatedApi(apiFunc, initialParams = {}) {
  const [params, setParams] = useState({
    page: 1,
    limit: 20,
    ...initialParams,
  });
  const [totalPages, setTotalPages] = useState(1);
  const [totalItems, setTotalItems] = useState(0);

  const { data, loading, error, refetch } = useApi(
    () => apiFunc(params),
    [JSON.stringify(params)],
    {
      transform: (response) => {
        if (response?.pagination) {
          setTotalPages(response.pagination.total_pages || 1);
          setTotalItems(response.pagination.total || 0);
        } else if (response?.total) {
          setTotalPages(Math.ceil(response.total / params.limit));
          setTotalItems(response.total);
        }
        return response?.data || response?.items || response;
      },
    }
  );

  const goToPage = useCallback((page) => {
    setParams((prev) => ({ ...prev, page }));
  }, []);

  const nextPage = useCallback(() => {
    setParams((prev) => ({
      ...prev,
      page: Math.min(prev.page + 1, totalPages),
    }));
  }, [totalPages]);

  const prevPage = useCallback(() => {
    setParams((prev) => ({
      ...prev,
      page: Math.max(prev.page - 1, 1),
    }));
  }, []);

  const updateParams = useCallback((newParams) => {
    setParams((prev) => ({ ...prev, ...newParams, page: 1 }));
  }, []);

  return {
    data,
    loading,
    error,
    params,
    totalPages,
    totalItems,
    currentPage: params.page,
    goToPage,
    nextPage,
    prevPage,
    updateParams,
    refetch,
  };
}

/**
 * Hook for polling API calls at intervals.
 */
export function usePolling(apiFunc, interval = 5000, deps = []) {
  const { data, loading, error, refetch, setData } = useApi(apiFunc, deps);
  const intervalRef = useRef(null);

  useEffect(() => {
    intervalRef.current = setInterval(() => {
      refetch();
    }, interval);

    return () => {
      if (intervalRef.current) {
        clearInterval(intervalRef.current);
      }
    };
  }, [interval, refetch]);

  const stopPolling = useCallback(() => {
    if (intervalRef.current) {
      clearInterval(intervalRef.current);
      intervalRef.current = null;
    }
  }, []);

  return { data, loading, error, refetch, setData, stopPolling };
}

export default useApi;
