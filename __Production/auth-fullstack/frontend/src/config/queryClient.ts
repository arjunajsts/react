import { QueryClient } from "@tanstack/react-query";

export const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      retry: false,
      staleTime: 0, // Data becomes stale immediately
      refetchOnWindowFocus: true,
    },
  },
});
