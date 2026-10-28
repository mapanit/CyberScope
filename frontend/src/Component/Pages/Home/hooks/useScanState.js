import { useState, useRef } from 'react';
import { apiFetch } from '../../../../api';

/**
 * Hook для управления состоянием сканирования
 */
export const useScanState = () => {
    const [activeTools, setActiveTools] = useState([]);
    const [query, setQuery] = useState('');
    const [loading, setLoading] = useState(false);
    const [scanProgress, setScanProgress] = useState(null);
    const [results, setResults] = useState(null);
    const [scanAborted, setScanAborted] = useState(false);
    const [allowInternal, setAllowInternal] = useState(true);
    const [expandedJsonTools, setExpandedJsonTools] = useState({});
    const [localPath, setLocalPath] = useState("");
    // Refs для управления отменой запросов
    const abortControllerRef = useRef(null);
    const scanIdRef = useRef(null);
    const readerRefs = useRef({});

    const abortAllRequests = () => {
        if (abortControllerRef.current) {
            abortControllerRef.current.abort();
            abortControllerRef.current = null;
        }
        
        Object.values(readerRefs.current).forEach(reader => {
            if (reader && typeof reader.cancel === 'function') {
                reader.cancel();
            }
        });
        readerRefs.current = {};
    };

    const cancelScan = () => {
        if (scanIdRef.current) {
            const params = new URLSearchParams({ scan_id: scanIdRef.current });
            apiFetch(`/api/cancel-scan?${params}`, { method: 'POST' }).catch((error) => {
                console.error('Ошибка отмены сканирования на сервере:', error);
            });
        }
        abortAllRequests();
        setScanAborted(true);
        setLoading(false);
        alert('Запрос на отмену отправлен. Текущая проверка может завершиться не сразу.');
    };

    return {
        activeTools, setActiveTools,
        query, setQuery,
        loading, setLoading,
        scanProgress, setScanProgress,
        results, setResults,
        scanAborted, setScanAborted,
        allowInternal, setAllowInternal,
        expandedJsonTools, setExpandedJsonTools,
        abortControllerRef, scanIdRef, readerRefs,
        abortAllRequests, cancelScan,
        localPath,
  setLocalPath,
    };
};
