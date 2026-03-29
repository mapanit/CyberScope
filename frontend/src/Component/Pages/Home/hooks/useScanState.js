import { useState, useRef } from 'react';

/**
 * Hook для управления состоянием сканирования
 */
export const useScanState = () => {
    const [activeTools, setActiveTools] = useState([]);
    const [query, setQuery] = useState('');
    const [loading, setLoading] = useState(false);
    const [results, setResults] = useState(null);
    const [scanAborted, setScanAborted] = useState(false);
    const [allowInternal, setAllowInternal] = useState(true);
    const [expandedJsonTools, setExpandedJsonTools] = useState({});
    
    // Refs для управления отменой запросов
    const abortControllerRef = useRef(null);
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
        abortAllRequests();
        setScanAborted(true);
        setLoading(false);
        alert('Сканирование отменено');
    };

    return {
        activeTools, setActiveTools,
        query, setQuery,
        loading, setLoading,
        results, setResults,
        scanAborted, setScanAborted,
        allowInternal, setAllowInternal,
        expandedJsonTools, setExpandedJsonTools,
        abortControllerRef, readerRefs,
        abortAllRequests, cancelScan
    };
};
